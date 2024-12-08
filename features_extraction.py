import re
import ssl
import socket
import requests
import whois
import urllib.parse
import os
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from ipwhois import IPWhois
from googlesearch import search
from patterns import * 

# Tắt cảnh báo SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# This import is needed only when you run this file in isolation.
import sys

# Path of your local server. Different for different OSs.
LOCALHOST_PATH = "./"
DIRECTORY_NAME = ""

# This function checks if the URL has an IP address.
def having_ip_address(url):
    """Kiểm tra URL có chứa địa chỉ IP không
    Returns:
        -1: Phishing (có IP)
        1: Legitimate (không có IP)
    """
    try:
        # Đảm bảo patterns được định nghĩa là string
        ip_pattern = str(ipv4_pattern + "|" + ipv6_pattern)
        match = re.search(ip_pattern, url)
        return -1 if match else 1
    except Exception as e:
        print(f"Error in having_ip_address: {str(e)}")
        return -1

# This function checks the length of the URL.
def url_length(url):
    """Kiểm tra độ dài URL
    Returns:
        1: Legitimate (<54)
        0: Suspicious (54-75)
        -1: Phishing (>75)
    """
    try:
        if len(url) < 54:
            return 1
        if 54 <= len(url) <= 75:
            return 0
        return -1
    except Exception as e:
        print(f"Error in url_length: {str(e)}")
        return -1

# This function checks if the URL is a shortening service.
def shortening_service(url):
    """Kiểm tra URL có phải dịch vụ rút gọn không
    Returns:
        -1: Phishing (là URL rút gọn)
        1: Legitimate (không phải URL rút gọn)
    """
    try:
        match = re.search(str(shortening_services), url)
        return -1 if match else 1
    except Exception as e:
        print(f"Error in shortening_service: {str(e)}")
        return -1

# This function checks if the URL has an @ symbol.
def having_at_symbol(url):
    """Kiểm tra URL có chứa ký tự @ không
    Returns:
        -1: Phishing (có @)
        1: Legitimate (không có @)
    """
    try:
        match = re.search('@', url)
        return -1 if match else 1
    except Exception as e:
        print(f"Error in having_at_symbol: {str(e)}")
        return -1

# This function checks if the URL has a double slash.
def double_slash_redirecting(url):
    """Kiểm tra URL có chứa // sau vị trí thứ 7 không
    Returns:
        -1: Phishing (có //)
        1: Legitimate (không có //)
    """
    try:
        last_double_slash = url.rfind('//')
        return -1 if last_double_slash > 6 else 1
    except Exception as e:
        print(f"Error in double_slash_redirecting: {str(e)}")
        return -1

# This function checks if the URL has a - symbol.
def prefix_suffix(domain):
    """Kiểm tra domain có chứa dấu - không
    Returns:
        -1: Phishing (có -)
        1: Legitimate (không có -)
    """
    try:
        match = re.search('-', domain)
        return -1 if match else 1
    except Exception as e:
        print(f"Error in prefix_suffix: {str(e)}")
        return -1

# This function checks the number of subdomains in a URL to determine if it's potentially suspicious.
# It first checks if the URL contains an IP address, and if so, removes it from consideration.
# Then it counts the number of dots (.) in the remaining URL to estimate the number of subdomains.
def having_sub_domain(url):
    """Kiểm tra số lượng subdomain
    Returns:
        1: Legitimate (≤3 dots)
        0: Suspicious (4 dots)
        -1: Phishing (>4 dots hoặc có IP)
    """
    try:
        if having_ip_address(url) == -1:
            # Đảm bảo pattern là string
            ip_pattern = str('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                           '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}')
            match = re.search(ip_pattern, url)
            pos = match.end()
            url = url[pos:]
            
        num_dots = len(re.findall(r'\.', url))
        if num_dots <= 3:
            return 1
        elif num_dots == 4:
            return 0
        else:
            return -1
    except Exception as e:
        print(f"Error in having_sub_domain: {str(e)}")
        return -1

# This function checks the domain registration length to determine if it's potentially suspicious.
# It calculates the time between the current date and the domain's expiration date.
# If the registration length is less than or equal to 1 year, it's considered suspicious.
def domain_registration_length(domain):
    """Kiểm tra thời gian đăng ký domain
    Returns:
        1: Legitimate (>1 năm)
        -1: Phishing (<=1 năm hoặc không có thông tin)
    """
    try:
        expiration_date = domain.expiration_date
        creation_date = domain.creation_date
        
        # Xử lý trường hợp nhiều ngày
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        # Chuyển đổi string thành datetime nếu cần
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
            
        # Tính thời gian đăng ký
        if expiration_date and creation_date:
            registration_length = (expiration_date - creation_date).days
            return -1 if registration_length / 365 <= 1 else 1
            
    except Exception as e:
        print(f"Error in domain_registration_length: {str(e)}")
        
    return -1  # Return phishing nếu có lỗi hoặc không có thông tin

# This function checks if the favicon of a webpage is legitimate.
# It searches for the favicon link in the HTML head and checks if:
# 1. The favicon URL contains the wiki domain
# 2. The favicon URL has only one dot (indicating it's from the same domain)
# 3. The favicon URL contains the main domain
def favicon(url, soup, domain):
    """Kiểm tra favicon có được tải từ domain khác không
    Returns:
        -1: Phishing (favicon từ domain khác)
        1: Legitimate (favicon từ cùng domain hoặc không có favicon)
    """
    try:
        # Tìm favicon trong thẻ link với rel="icon" hoặc rel="shortcut icon"
        favicon_links = soup.find_all('link', rel=lambda x: x and ('icon' in x.lower()))
        
        if not favicon_links:
            return 1  # Không có favicon -> legitimate
            
        for link in favicon_links:
            if not link.has_attr('href'):
                continue
                
            href = link['href']
            
            # Nếu href là relative path, coi như cùng domain
            if href.startswith('/'):
                return 1
                
            # Nếu href là absolute path, kiểm tra domain
            try:
                favicon_domain = urllib.parse.urlparse(href).netloc
                if not favicon_domain:
                    return 1
                    
                # So sánh domain của favicon với domain của trang
                if domain in favicon_domain or favicon_domain in domain:
                    return 1
                else:
                    print(f"Favicon domain mismatch: {favicon_domain} vs {domain}")
                    return -1
                    
            except Exception as e:
                print(f"Error parsing favicon URL: {str(e)}")
                return -1
                
        return -1  # Không tìm thấy favicon hợp lệ
        
    except Exception as e:
        print(f"Error in favicon: {str(e)}")
        return -1

# This function checks if the URL contains 'http' or 'https' in an unusual place.
# It returns -1 if 'http' or 'https' is found in the URL after the protocol, 1 otherwise.
def https_token(url):
    """Kiểm tra token HTTPS trong URL
    Returns:
        -1: Phishing (có HTTPS không hợp lệ)
        1: Legitimate (HTTPS hợp lệ hoặc không có)
    """
    try:
        match = re.search(http_https, url)
        if match and match.start() == 0:
            url = url[match.end():]
        match = re.search('http|https', url)
        return -1 if match else 1
    except Exception as e:
        print(f"Error in https_token: {str(e)}")
        return -1

# This function analyzes the sources of various media elements (img, audio, embed, iframe) in the HTML.
# It checks if these sources are from the same domain or a trusted source.
# Returns 1 if less than 22% of sources are suspicious, 0 if between 22% and 61%, and -1 if more than 61%.
def request_url(wiki, soup, domain):
    """Kiểm tra các URL trong tài nguyên
    Returns:
        1: Legitimate (<22% suspicious)
        0: Suspicious (22-61% suspicious)
        -1: Phishing (>61% suspicious)
    """
    try:
        i = 0
        success = 0
        
        for img in soup.find_all('img', src=True):
            dots = [x.start() for x in re.finditer(r'\.', img['src'])]
            if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
                success += 1
            i += 1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
            if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success += 1
            i += 1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
            if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success += 1
            i += 1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start() for x in re.finditer(r'\.', iframe['src'])]
            if wiki in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success += 1
            i += 1

        try:
            percentage = success / float(i) * 100
        except:
            return 1

        if percentage < 22.0:
            return 1
        elif 22.0 <= percentage < 61.0:
            return 0
        else:
            return -1
    except Exception as e:
        print(f"Error in request_url: {str(e)}")
        return -1

# This function analyzes the URLs in anchor tags.
# It checks for suspicious href attributes like "#", "javascript", or "mailto".
# Returns 1 if less than 31% of links are suspicious, 0 if between 31% and 67%, and -1 if more than 67%.
def url_of_anchor(url, soup, domain):
    """Kiểm tra các anchor tags
    Returns:
        1: Legitimate (<31% suspicious)
        0: Suspicious (31-67% suspicious)
        -1: Phishing (>67% suspicious)
    """
    try:
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe += 1
            i += 1
        try:
            percentage = unsafe / float(i) * 100
        except:
            return 1
        
        if percentage < 31.0:
            return 1
        elif 31.0 <= percentage < 67.0:
            return 0
        else:
            return -1
    except Exception as e:
        print(f"Error in url_of_anchor: {str(e)}")
        return -1

# This function checks the sources of <link> and <script> tags.
# It verifies if these sources are from the same domain or a trusted source.
# Returns 1 if less than 17% of sources are suspicious, 0 if between 17% and 81%, and -1 if more than 81%.
def links_in_tags(url, soup, domain):
    """Kiểm tra các Meta, Script và Link tags
    Returns:
        1: Legitimate (<17% suspicious)
        0: Suspicious (17-81% suspicious)
        -1: Phishing (>81% suspicious)
    """
    try:
        i = 0
        success = 0
        
        for link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', link['href'])]
            if domain in link['href'] or len(dots) == 1:
                success += 1
            i += 1

        for script in soup.find_all('script', src=True):
            dots = [x.start() for x in re.finditer(r'\.', script['src'])]
            if domain in script['src'] or len(dots) == 1:
                success += 1
            i += 1
            
        try:
            percentage = success / float(i) * 100
        except:
            return 1

        if percentage < 17.0:
            return 1
        elif 17.0 <= percentage < 81.0:
            return 0
        else:
            return -1
    except Exception as e:
        print(f"Error in links_in_tags: {str(e)}")
        return -1

# This function checks the Server Form Handler (SFH) for potential phishing attempts.
# It examines the 'action' attribute of form tags.
# Returns -1 if the action is empty or "about:blank", 0 if it's to an external domain, and 1 if it's safe.
def sfh(url, soup, domain):
    """Kiểm tra Server Form Handler
    Returns:
        1: Legitimate (SFH thuộc domain)
        0: Suspicious (SFH about:blank hoặc "")
        -1: Phishing (SFH khác domain)
    """
    try:
        for form in soup.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                return 0
            elif url not in form['action'] and domain not in form['action']:
                return -1
            else:
                return 1
        return 1
    except Exception as e:
        print(f"Error in sfh: {str(e)}")
        return -1

# This function checks if the form is submitting information to an email address.
# It looks for "mailto:" in the form's action attribute.
# Returns -1 if "mailto:" is found, 1 otherwise.
def submitting_to_email(soup):
    """Kiểm tra form submit đến email
    Returns:
        -1: Phishing (submit đến email)
        1: Legitimate (không submit đến email)
    """
    try:
        for form in soup.find_all('form', action=True):
            if "mailto:" in form['action']:
                return -1
        return 1
    except Exception as e:
        print(f"Error in submitting_to_email: {str(e)}")
        return -1

# This function checks if the URL is abnormal by comparing it with the domain name.
# Returns 1 if the domain name is found in the URL, -1 otherwise.
def abnormal_url(domain, url):
    """Kiểm tra URL bất thường
    Returns:
        -1: Phishing (domain không khớp với hostname)
        1: Legitimate (domain khớp với hostname)
    """
    try:
        hostname = domain.domain_name
        if isinstance(hostname, list):
            hostname = hostname[0]
        match = re.search(hostname.lower(), url.lower())    
        return 1 if match else -1
    except Exception as e:
        print(f"Error in abnormal_url: {str(e)}")
        return -1

# This function checks for suspicious iframes in the HTML.
# It looks for iframes with zero width, height, or frameBorder.
# Returns -1 if a suspicious iframe is found, 0 if partially suspicious, and 1 if all iframes are safe.
def i_frame(soup):
    """Kiểm tra thẻ iframe
    Returns:
        -1: Phishing (có iframe)
        1: Legitimate (không có iframe)
    """
    try:
        for iframe in soup.find_all('iframe', frameborder=True):
            if iframe['frameborder'] == "0":
                return -1
        return 1
    except Exception as e:
        print(f"Error in iframe: {str(e)}")
        return -1

# This function checks the age of the domain.
# It calculates the time between the creation date and expiration date.
# Returns -1 if the domain is less than 6 months old, 1 otherwise.
def age_of_domain(domain):
    """Kiểm tra tuổi của domain
    Returns:
        1: Legitimate (>6 tháng)
        -1: Phishing (<=6 tháng hoặc không có thông tin)
    """
    try:
        expiration_date = domain.expiration_date
        creation_date = domain.creation_date
        
        # Xử lý trường hợp nhiều ngày
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        # Chuyển đổi string thành datetime nếu cần
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
            
        # Tính tuổi domain
        if expiration_date and creation_date:
            age_days = abs((expiration_date - creation_date).days)
            return -1 if age_days / 30 < 6 else 1
            
    except Exception as e:
        print(f"Error in age_of_domain: {str(e)}")
        
    return -1  # Return phishing nếu có lỗi hoặc không có thông tin


def web_traffic(url):
    """Kiểm tra traffic rank của website từ Majestic Million dataset
    Args:
        url: URL cần kiểm tra
    Returns:
        1: Legitimate (rank < 100,000)
        0: Suspicious (rank >= 100,000) 
        -1: Phishing (không có trong dataset)
    """
    try:
        # Đọc domain từ URL
        # Lấy domain name từ URL
        domain = get_hostname_from_url(url)
        # Loại bỏ www. nếu có
        if domain.startswith('www.'):
            domain = domain[4:]
        # Đọc CSV file
        csv_path = "./Other Information/majestic_million.csv"
        if not os.path.exists(csv_path):
            return -1
            
        df = pd.read_csv(csv_path, usecols=['Domain','GlobalRank'])
        
        # Tìm domain trong dataset
        rank = df[df['Domain'] == domain]['GlobalRank'].values
        if len(rank) > 0:
            # Phân loại dựa trên rank
            return 1 if rank[0] < 100000 else 0
        else:
            return -1  # Domain không có trong dataset
            
    except Exception as e:
        print(f"Error in web_traffic: {str(e)}")
        return -1

# This function checks if the URL is indexed by Google.
# It performs a Google search for the URL and checks if it appears in the results.
# Returns 1 if the URL is indexed, -1 if it's not.
def google_index(url):
    site = search(url, 5)
    return 1 if site else -1

# This function performs a statistical analysis of the URL and IP address.
# It checks against lists of known phishing URLs and IP addresses.
# Returns -1 if the URL or IP is found in the blacklists, 1 otherwise.
def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        return -1
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1

# This function extracts the hostname from a given URL.
# It removes the protocol (http://, https://, www   .) and any path after the domain.
def get_hostname_from_url(url):
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    pattern = "https://|http://|www.|https://www.|http://www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname

# TODO: Put the DNS and domain code into a function.

def check_port(url):
    """Kiểm tra port của URL
    Returns:
        -1: Phishing (sử dụng port không tiêu chuẩn)
        1: Legitimate (sử dụng port tiêu chuẩn hoặc không chỉ định port)
    """
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
        
        # Danh sách các port tiêu chuẩn và trạng thái ưu tiên
        standard_ports = {
            21: False,  # FTP
            22: False,  # SSH
            23: False,  # Telnet
            80: True,   # HTTP
            443: True,  # HTTPS
            445: False, # SMB
            1433: False,# SQL Server
            1521: False,# Oracle
            3306: False,# MySQL
            3389: False # RDP
        }
        
        if port is None:
            return 1  # Không chỉ định port -> an toàn
            
        if port in standard_ports:
            return 1 if standard_ports[port] else -1
        else:
            return -1  # Port không tiêu chuẩn -> nguy hiểm
            
    except Exception as e:
        print(f"Error in check_port: {str(e)}")
        return 1  # Trả về an toàn nếu không thể kiểm tra

def check_redirect(url):
    """Kiểm tra số lần redirect của URL
    Returns:
        1: Legitimate (≤1 lần redirect)
        0: Suspicious (2-3 lần redirect)
        -1: Phishing (≥4 lần redirect)
    """
    try:
        # Tạo session để theo dõi redirects
        session = requests.Session()
        
        # Disable SSL verification để tránh lỗi với các site không có SSL
        session.verify = False
        
        # Đếm số lần redirect
        response = session.get(url, allow_redirects=True, timeout=5)
        redirect_count = len(response.history)
        
        # Phân loại theo quy tắc
        if redirect_count <= 1:
            return 1    # Legitimate
        elif 2 <= redirect_count < 4:
            return 0    # Suspicious
        else:
            return -1   # Phishing (≥4 redirects)
            
    except Exception as e:
        print(f"Error in check_redirect: {str(e)}")
        return -1  # Return phishing nếu có lỗi

def check_mouseover(soup):
    """Kiểm tra sự kiện onMouseOver
    Returns:
        -1: Phishing (có thay đổi status bar)
        1: Legitimate (không thay đổi status bar)
    """
    # Định nghĩa patterns ở ngoài try block
    suspicious_patterns = [
        'window.status',
        'status=',
        'statusbar',
        'status_bar',
        'statusline',
        'status_line'
    ]
    
    try:
        # Tìm tất cả các thẻ có sự kiện onmouseover
        for tag in soup.find_all(onmouseover=True):
            mouseover_content = tag.get('onmouseover', '').lower()
            
            # Nếu tìm thấy bất kỳ pattern nào
            if any(pattern in mouseover_content for pattern in suspicious_patterns):
                return -1  # Phishing
                
        # Kiểm tra trong các thẻ script
        for script in soup.find_all('script'):
            if script.string:
                script_content = script.string.lower()
                # Kiểm tra các đoạn JavaScript thay đổi status bar
                if any(pattern in script_content for pattern in suspicious_patterns):
                    return -1  # Phishing
        
        return 1  # Legitimate (không tìm thấy dấu hiệu thay đổi status bar)
            
    except Exception as e:
        print(f"Error in mouseover: {str(e)}")
        return -1

def check_right_click(soup):
    """Kiểm tra chặn right-click
    Returns:
        -1: Phishing (chặn right-click)
        1: Legitimate (không chặn)
    """
    try:
        # Tìm tất cả các thẻ script
        for script in soup.find_all('script'):
            if script.string:
                script_content = script.string.lower()
                
                # Các pattern chặn right click phổ biến
                suspicious_patterns = [
                    'event.button==2',
                    'event.button===2',
                    'event.button == 2',
                    'event.button === 2',
                    'oncontextmenu="return false"',
                    'addEventListener("contextmenu"',
                    'onmousedown="return false"',
                    'document.oncontextmenu',
                    'document.onmousedown',
                    'preventDefault()',
                    'contextmenu'
                ]
                
                # Nếu tìm thấy bất kỳ pattern nào
                if any(pattern in script_content for pattern in suspicious_patterns):
                    return -1  # Phishing
        
        # Kiểm tra các thuộc tính oncontextmenu trên các thẻ HTML
        for tag in soup.find_all(oncontextmenu=True):
            if 'return false' in tag['oncontextmenu'].lower():
                return -1  # Phishing
                
        return 1  # Legitimate (không tìm thấy dấu hiệu chặn right click)
            
    except Exception as e:
        print(f"Error in rightclick: {str(e)}")
        return -1

def check_popup(soup):
    """Kiểm tra popup yêu cầu thông tin
    Returns:
        -1: Phishing (có popup yêu cầu thông tin)
        1: Legitimate (không có popup)
    """
    try:
        # Tìm tất cả các thẻ script
        for script in soup.find_all('script'):
            if script.string:
                script_content = script.string.lower()
                
                # Kiểm tra có popup window không
                popup_patterns = [
                    'window.open',
                    'popup',
                    'modal',
                    'dialog'
                ]
                
                # Nếu tìm thấy popup
                if any(pattern in script_content for pattern in popup_patterns):
                    # Kiểm tra popup có chứa form nhập liệu không
                    input_patterns = [
                        'input',
                        'text',
                        'password',
                        'email',
                        'tel',
                        'number',
                        'form',
                        'textfield',
                        'textbox'
                    ]
                    
                    # Nếu popup chứa form nhập liệu
                    if any(pattern in script_content for pattern in input_patterns):
                        return -1  # Phishing
        
        # Kiểm tra các div có class/id chứa từ khóa popup/modal
        popup_elements = soup.find_all(class_=lambda x: x and ('popup' in x.lower() or 'modal' in x.lower()))
        popup_elements.extend(soup.find_all(id=lambda x: x and ('popup' in x.lower() or 'modal' in x.lower())))
        
        for element in popup_elements:
            # Kiểm tra có input fields trong popup không
            if element.find_all(['input', 'textarea']):
                return -1  # Phishing
                
        return 1  # Legitimate (không tìm thấy popup nguy hiểm)
            
    except Exception as e:
        print(f"Error in popup: {str(e)}")
        return -1

def page_rank(url):
    """Kiểm tra PageRank của website
    Returns:
        -1: Phishing (PageRank < 0.2 hoặc không có)
        1: Legitimate (PageRank >= 0.2)
    """
    try:
        headers = {
            'API-OPR': 'wk8cww0w8ow8oo84g40kgsc8sgsso4okcgkssk88',
            'Content-Type': 'application/json'
        }
        
        domain = get_hostname_from_url(url)
        api_url = f'https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}'
        
        response = requests.get(api_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            # Lấy giá trị PageRank từ response
            try:
                page_rank_value = float(data['response'][0]['page_rank_decimal'])
                # Áp dụng quy tắc
                return 1 if page_rank_value >= 0.2 else -1
            except (KeyError, ValueError, IndexError):
                return -1  # Không có PageRank -> Phishing
        else:
            return -1  # Lỗi API -> coi như không có PageRank
            
    except Exception as e:
        print(f"Error in page_rank: {str(e)}")
        return -1  # Xử lý lỗi -> coi như không có PageRank

def links_pointing(soup, domain):
    """Đếm số lượng links trỏ đến webpage
    Returns:
        -1: Phishing (0 links)
        0: Suspicious (1-2 links)
        1: Legitimate (>2 links)
    """
    try:
        # Đếm tất cả các links trỏ đến từ các thẻ a
        external_links = 0
        for a in soup.find_all('a', href=True):
            href = a['href']
            # Chỉ đếm external links (không cùng domain)
            if domain not in href and not href.startswith('/'):
                if href.startswith('http') or href.startswith('https'):
                    external_links += 1
        
        if external_links == 0:
            return -1  # Phishing
        elif 0 < external_links <= 2:
            return 0   # Suspicious
        else:
            return 1   # Legitimate (>2 links)
            
    except Exception as e:
        print(f"Error in links_pointing: {str(e)}")
        return -1  # Return phishing nếu có lỗi

def check_ssl_certificate(url):
    """Kiểm tra chi tiết về chứng chỉ SSL"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            return -1  # Phishing: Không sử dụng HTTPS
        
        # Tạo context SSL với verify mode
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Lấy chứng chỉ từ server
        with socket.create_connection((parsed.netloc, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                cert = ssock.getpeercert()
                
                # Kiểm tra thời gian chứng chỉ
                not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                not_before = ssl.cert_time_to_seconds(cert['notBefore'])
                cert_age = (not_after - not_before) / (365 * 24 * 60 * 60)  # Convert to years
                
                # Kiểm tra nhà phát hành
                issuer = cert.get('issuer', [])
                issuer_org = None
                for item in issuer:
                    if item[0][0] == 'organizationName':
                        issuer_org = item[0][1]

                trusted_issuers = [
                    # Global CAs
                    "DigiCert Inc",
                    "Google Trust Services",
                    "Let's Encrypt",
                    "GlobalSign",
                    "Sectigo Limited",
                    "Amazon Trust Services",
                    "IdenTrust",
                    "GoDaddy",
                    "Entrust",
                    "VeriSign",
                    # Regional CAs
                    "Comodo Security Solutions",
                    "Network Solutions",
                    "RapidSSL",
                    "Thawte",
                    "GeoTrust",
                    "QuoVadis",
                    "SSL.com",
                    "Trustwave",
                    "SECOM Trust Systems",
                    "SwissSign AG"
                ]
                
                # Nếu chứng chỉ hợp lệ hoặc được cấp bởi nhà phát hành đáng tin cậy
                if cert_age >= 1 or issuer_org in trusted_issuers:
                    return 1  # Legitimate
                elif cert_age < 1 and issuer_org not in trusted_issuers:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing

    except Exception as e:
        print(f"Error checking SSL certificate: {str(e)}")
        return -1  # Phishing: Lỗi kết nối hoặc không hợp lệ

def main(url):
    try:
        response = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        status = []
        hostname = get_hostname_from_url(url)
        
        # 1. Having IP address
        status.append(having_ip_address(url))
        
        # 2. URL Length
        status.append(url_length(url))
        
        # 3. Shortening Service
        status.append(shortening_service(url))
        
        # 4. Having @ Symbol
        status.append(having_at_symbol(url))
        
        # 5. Double Slash Redirecting
        status.append(double_slash_redirecting(url))
        
        # 6. Prefix Suffix
        status.append(prefix_suffix(hostname))
        
        # 7. Having Sub Domain
        status.append(having_sub_domain(url))

        dns = 1
        try:
            domain = whois.whois(hostname)
        except:
            dns = -1

        # 8. SSL final State
        status.append(-1 if dns == -1 else check_ssl_certificate(url))
        
        # 9. Domain Registration Length
        status.append(-1 if dns == -1 else domain_registration_length(domain))
        
        # 10. Favicon
        status.append(favicon(url, soup, hostname))
        
        # 11. Port
        status.append(check_port(url))
        
        # 12. HTTPS Token
        status.append(https_token(url))
        
        # 13. Request URL
        status.append(request_url(url, soup, hostname))
        
        # 14. URL of Anchor
        status.append(url_of_anchor(url, soup, hostname))
        
        # 15. Links in Tags
        status.append(links_in_tags(url, soup, hostname))
        
        # 16. SFH
        status.append(sfh(url, soup, hostname))
        
        # 17. Submitting to Email
        status.append(submitting_to_email(soup))
        
        # 18. Abnormal URL
        status.append(-1 if dns == -1 else abnormal_url(domain, url))
        
        # 19. Redirect
        status.append(check_redirect(url))
        
        # 20. On Mouseover
        status.append(check_mouseover(soup))
        
        # 21. RightClick
        status.append(check_right_click(soup))
        
        # 22. PopUpWindow
        status.append(check_popup(soup))
        
        # 23. Iframe
        status.append(i_frame(soup))
        
        # 24. Age of Domain
        status.append(-1 if dns == -1 else age_of_domain(domain))
        
        # 25. DNS Record
        status.append(dns)
        
        # 26. Web Traffic
        status.append(web_traffic(url))
        
        # 27. Page Rank
        status.append(page_rank(url))
        
        # 28. Google Index
        status.append(google_index(url))
        
        # 29. Links Pointing to Page
        status.append(links_pointing(soup, hostname))
        
        # 30. Statistical Report
        status.append(statistical_report(url, hostname))
        print(status)
        return status
        
    except Exception as e:
        print(f"Error in feature extraction: {str(e)}")
        return [0] * 30  # Trả về list 30 giá trị 0 nếu có lỗi


# Use the below two lines if features_extraction.py is being run as a standalone file. If you are running this file as
# a part of the workflow pipeline starting with the chrome extension, comment out these two lines.
# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Please use the following format for the command - `python2 features_extraction.py <url-to-be-tested>`")
#         exit(0)
#     main(sys.argv[1])
     