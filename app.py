import os
from flask import Flask, request, jsonify, send_from_directory
import dns.resolver
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, static_folder='static')

# GoHighLevel expected DNS configurations
# Sub-accounts (subdomains)
GHL_SUBACCOUNT_CNAME = 'brand.ludicrous.cloud'

# Websites/Funnels
GHL_SITES_A_RECORD = '162.159.140.166'
GHL_SITES_CNAME = 'sites.ludicrous.cloud'

# Client Portal
GHL_PORTAL_CNAME = 'clientportal.ludicrous.cloud'

# Sending Domain (Email) Requirements
GHL_SPF_INCLUDES = ['spf.leadconnectorhq.com', 'mailgun.org']
GHL_EMAIL_CNAME_TARGET = 'mailgun.org'
GHL_MX_RECORDS = ['mxa.mailgun.org', 'mxb.mailgun.org']


def check_dns_records(domain):
    """Check all DNS records for a domain."""
    results = {
        'domain': domain,
        'cname': None,
        'a_records': [],
        'mx_records': [],
        'txt_records': [],
        'errors': []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Check CNAME
    try:
        answers = resolver.resolve(domain, 'CNAME')
        results['cname'] = [str(rdata.target).rstrip('.') for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        results['errors'].append('Domain does not exist')
        return results
    except Exception as e:
        results['errors'].append(f'CNAME lookup error: {str(e)}')

    # Check A records
    try:
        answers = resolver.resolve(domain, 'A')
        results['a_records'] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        if 'Domain does not exist' not in str(results['errors']):
            results['errors'].append(f'A record lookup error: {str(e)}')

    # Check MX records
    try:
        answers = resolver.resolve(domain, 'MX')
        results['mx_records'] = [{'priority': rdata.preference, 'host': str(rdata.exchange).rstrip('.')} for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        pass

    # Check TXT records
    try:
        answers = resolver.resolve(domain, 'TXT')
        results['txt_records'] = [str(rdata).strip('"') for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        pass

    return results


def check_ssl(domain):
    """Check SSL certificate for a domain."""
    result = {
        'valid': False,
        'issuer': None,
        'expires': None,
        'error': None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['valid'] = True
                result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                result['expires'] = cert.get('notAfter')
    except ssl.SSLCertVerificationError as e:
        result['error'] = f'SSL verification failed: {str(e)}'
    except socket.timeout:
        result['error'] = 'Connection timeout'
    except socket.gaierror:
        result['error'] = 'Could not resolve domain'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused (port 443 not open)'
    except Exception as e:
        result['error'] = str(e)

    return result


def check_sending_domain(domain):
    """Check sending domain (email) DNS records."""
    results = {
        'spf': {'valid': False, 'record': None, 'issues': []},
        'dkim': {'valid': False, 'record': None, 'issues': []},
        'email_cname': {'valid': False, 'record': None, 'issues': []},
        'mx': {'valid': False, 'records': [], 'issues': []},
        'dmarc': {'valid': False, 'record': None, 'issues': []}
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Determine if subdomain or root domain
    parts = domain.split('.')
    is_subdomain = len(parts) > 2

    if is_subdomain:
        root_domain = '.'.join(parts[1:])
        email_host = domain
        mx_host = domain
        dmarc_host = f'_dmarc.{domain}'
    else:
        root_domain = domain
        email_host = domain
        mx_host = domain
        dmarc_host = f'_dmarc.{domain}'

    # Check SPF (TXT record on root domain)
    try:
        answers = resolver.resolve(root_domain, 'TXT')
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if txt_value.startswith('v=spf1'):
                results['spf']['record'] = txt_value
                has_lc = 'spf.leadconnectorhq.com' in txt_value
                has_mailgun = 'mailgun.org' in txt_value
                if has_lc and has_mailgun:
                    results['spf']['valid'] = True
                else:
                    if not has_lc:
                        results['spf']['issues'].append('Missing: include:spf.leadconnectorhq.com')
                    if not has_mailgun:
                        results['spf']['issues'].append('Missing: include:mailgun.org')
                break
    except Exception:
        results['spf']['issues'].append('No SPF record found')

    # Check DKIM (TXT record on domain)
    try:
        answers = resolver.resolve(email_host, 'TXT')
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if 'k=rsa' in txt_value and 'p=' in txt_value:
                results['dkim']['record'] = txt_value[:50] + '...' if len(txt_value) > 50 else txt_value
                results['dkim']['valid'] = True
                break
        if not results['dkim']['valid']:
            results['dkim']['issues'].append(f'No DKIM record found on {email_host}')
    except Exception:
        results['dkim']['issues'].append(f'No DKIM record found on {email_host}')

    # Check email CNAME (email.[subdomain].root -> mailgun.org)
    email_domain = f'email.{domain}'
    try:
        answers = resolver.resolve(email_domain, 'CNAME')
        for rdata in answers:
            cname_value = str(rdata.target).rstrip('.')
            results['email_cname']['record'] = cname_value
            if GHL_EMAIL_CNAME_TARGET in cname_value:
                results['email_cname']['valid'] = True
            else:
                results['email_cname']['issues'].append(f'Should point to {GHL_EMAIL_CNAME_TARGET}')
            break
    except Exception:
        results['email_cname']['issues'].append(f'No CNAME record found for email.{domain}')

    # Check MX records
    try:
        answers = resolver.resolve(mx_host, 'MX')
        mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in answers]
        results['mx']['records'] = mx_hosts

        has_mxa = any('mxa.mailgun.org' in h for h in mx_hosts)
        has_mxb = any('mxb.mailgun.org' in h for h in mx_hosts)

        if has_mxa and has_mxb:
            results['mx']['valid'] = True
        else:
            if not has_mxa:
                results['mx']['issues'].append('Missing MX: mxa.mailgun.org')
            if not has_mxb:
                results['mx']['issues'].append('Missing MX: mxb.mailgun.org')
    except Exception:
        results['mx']['issues'].append(f'No MX records found on {mx_host}')

    # Check DMARC (TXT record on _dmarc.[domain])
    try:
        answers = resolver.resolve(dmarc_host, 'TXT')
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if txt_value.startswith('v=DMARC1'):
                results['dmarc']['record'] = txt_value
                results['dmarc']['valid'] = True
                break
        if not results['dmarc']['valid']:
            results['dmarc']['issues'].append('No DMARC record found')
    except Exception:
        results['dmarc']['issues'].append(f'No DMARC record found at {dmarc_host}')

    return results


def check_connectivity(domain):
    """Check if domain is reachable via HTTP/HTTPS."""
    import requests

    result = {
        'http': {'reachable': False, 'status_code': None, 'redirect': None},
        'https': {'reachable': False, 'status_code': None, 'redirect': None}
    }

    for protocol in ['http', 'https']:
        try:
            url = f'{protocol}://{domain}'
            resp = requests.get(url, timeout=10, allow_redirects=False)
            result[protocol]['reachable'] = True
            result[protocol]['status_code'] = resp.status_code
            if resp.is_redirect or resp.status_code in [301, 302, 303, 307, 308]:
                result[protocol]['redirect'] = resp.headers.get('Location')
        except requests.exceptions.SSLError as e:
            result[protocol]['error'] = 'SSL error'
        except requests.exceptions.Timeout:
            result[protocol]['error'] = 'Timeout'
        except requests.exceptions.ConnectionError:
            result[protocol]['error'] = 'Connection failed'
        except Exception as e:
            result[protocol]['error'] = str(e)

    return result


def validate_ghl_setup(dns_results, ssl_results, sending_domain_results=None):
    """Validate DNS configuration for each GHL feature."""
    domain = dns_results.get('domain', '')
    parts = domain.split('.')
    is_subdomain = len(parts) > 2

    # Get current CNAME if any
    current_cname = None
    if dns_results.get('cname'):
        current_cname = dns_results['cname'][0] if dns_results['cname'] else None

    # Build feature-centric validation
    features = {
        'branded_domain': {
            'name': 'Branded Domain',
            'setup_url': 'https://app.gohighlevel.com/v2/location/{{location.id}}/settings/company',
            'records': [
                {
                    'type': 'CNAME',
                    'host': domain,
                    'required': GHL_SUBACCOUNT_CNAME,
                    'current': current_cname,
                    'valid': current_cname and GHL_SUBACCOUNT_CNAME in current_cname
                }
            ]
        },
        'sites_funnels': {
            'name': 'Sites / Funnels',
            'setup_url': 'https://app.gohighlevel.com/v2/location/{{location.id}}/settings/domain',
            'records': [
                {
                    'type': 'A',
                    'host': '@',
                    'required': GHL_SITES_A_RECORD,
                    'current': ', '.join(dns_results.get('a_records', [])) or None,
                    'valid': GHL_SITES_A_RECORD in dns_results.get('a_records', [])
                },
                {
                    'type': 'CNAME',
                    'host': 'www',
                    'required': GHL_SITES_CNAME,
                    'current': current_cname,
                    'valid': current_cname and GHL_SITES_CNAME in current_cname
                }
            ]
        },
        'client_portal': {
            'name': 'Client Portal',
            'setup_url': 'https://app.gohighlevel.com/v2/location/{{location.id}}/memberships/client-portal/domain-setup',
            'records': [
                {
                    'type': 'CNAME',
                    'host': domain,
                    'required': GHL_PORTAL_CNAME,
                    'current': current_cname,
                    'valid': current_cname and GHL_PORTAL_CNAME in current_cname
                }
            ]
        }
    }

    # Add email/sending domain feature
    if sending_domain_results:
        features['sending_domain'] = {
            'name': 'Email / Sending Domain',
            'setup_url': 'https://app.gohighlevel.com/v2/location/{{location.id}}/settings/smtp_service/dedicated-domains',
            'records': [
                {
                    'type': 'TXT (SPF)',
                    'host': 'Root domain',
                    'required': 'v=spf1 include:spf.leadconnectorhq.com include:mailgun.org ~all',
                    'current': sending_domain_results['spf'].get('record'),
                    'valid': sending_domain_results['spf']['valid']
                },
                {
                    'type': 'TXT (DKIM)',
                    'host': domain,
                    'required': 'k=rsa; p=...',
                    'current': sending_domain_results['dkim'].get('record'),
                    'valid': sending_domain_results['dkim']['valid']
                },
                {
                    'type': 'CNAME',
                    'host': f'email.{domain}',
                    'required': GHL_EMAIL_CNAME_TARGET,
                    'current': sending_domain_results['email_cname'].get('record'),
                    'valid': sending_domain_results['email_cname']['valid']
                },
                {
                    'type': 'MX',
                    'host': domain,
                    'required': 'mxa.mailgun.org, mxb.mailgun.org',
                    'current': ', '.join(sending_domain_results['mx'].get('records', [])) or None,
                    'valid': sending_domain_results['mx']['valid']
                },
                {
                    'type': 'TXT (DMARC)',
                    'host': f'_dmarc.{domain}',
                    'required': 'v=DMARC1; p=...',
                    'current': sending_domain_results['dmarc'].get('record'),
                    'valid': sending_domain_results['dmarc']['valid']
                }
            ]
        }

    # Calculate which features are fully configured
    for key, feature in features.items():
        feature['all_valid'] = all(r['valid'] for r in feature['records'])
        feature['any_valid'] = any(r['valid'] for r in feature['records'])

    # SSL status
    ssl_valid = ssl_results.get('valid', False)

    return {
        'features': features,
        'ssl': {
            'valid': ssl_valid,
            'error': ssl_results.get('error'),
            'expires': ssl_results.get('expires')
        }
    }


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/check', methods=['POST'])
def check_domain():
    """Check a single domain."""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # Remove protocol if present
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

    dns_results = check_dns_records(domain)
    ssl_results = check_ssl(domain)
    connectivity = check_connectivity(domain)
    sending_domain = check_sending_domain(domain)

    ghl_validation = validate_ghl_setup(dns_results, ssl_results, sending_domain)

    return jsonify({
        'domain': domain,
        'ghl_validation': ghl_validation,
        'connectivity': connectivity
    })


@app.route('/api/bulk-check', methods=['POST'])
def bulk_check():
    """Check multiple domains."""
    data = request.get_json()
    domains = data.get('domains', [])

    if not domains:
        return jsonify({'error': 'Domains list is required'}), 400

    if len(domains) > 50:
        return jsonify({'error': 'Maximum 50 domains per request'}), 400

    results = []

    def check_single(domain):
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        dns_results = check_dns_records(domain)
        ssl_results = check_ssl(domain)
        connectivity = check_connectivity(domain)
        sending_domain = check_sending_domain(domain)

        ghl_validation = validate_ghl_setup(dns_results, ssl_results, sending_domain)

        return {
            'domain': domain,
            'ghl_validation': ghl_validation,
            'connectivity': connectivity
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_single, d): d for d in domains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                results.append({
                    'domain': futures[future],
                    'error': str(e)
                })

    return jsonify({'results': results})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=False, host='0.0.0.0', port=port)
