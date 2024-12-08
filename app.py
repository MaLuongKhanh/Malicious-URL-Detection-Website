import streamlit as st
import features_extraction
import test
import numpy as np
import shutil
from screenshotone import Client, TakeOptions
import requests
import socket
import geocoder
from urllib.parse import urlparse
from datetime import datetime
import whois
from ipwhois import IPWhois
    
def get_screenshot(url):
    try:
        client = Client('qIIcbKJyRMI51w', 'r0Tl7Edxj_E0hg')
        options = (TakeOptions.url(url)
            .format("png")
            .viewport_width(800)
            .viewport_height(600)
            .block_cookie_banners(True)
            .block_chats(True)
            .timeout(10))
        
        image = client.take(options)
        
        if image is None:
            st.error("⚠️ Unable to capture screenshot. The website might be blocking automated access.")
            return None
            
        # Lưu ảnh tạm thời
        temp_image_path = 'temp_screenshot.png'
        with open(temp_image_path, 'wb') as result_file:
            shutil.copyfileobj(image, result_file)
            
        return temp_image_path
        
    except requests.Timeout:
        st.error("⚠️ Screenshot capture timed out. Please try again.")
        return None
    except Exception as e:
        st.error(f"⚠️ Unexpected error while capturing screenshot: {str(e)}")
        return None

def get_url_info(url):
    try:
        source_url = url
        
        # Tạo session với SSL verification linh hoạt
        session = requests.Session()
        session.verify = False  # Tắt SSL verification
        
        # Thêm headers để giả lập trình duyệt
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Thực hiện request với session đã cấu hình
        response = session.get(url, headers=headers, timeout=10)
        directed_url = response.url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        
        try:
            ip_address = socket.gethostbyname(domain)
            g = geocoder.ip(ip_address)
            country = g.country if g.country else "Unknown"
            
            ipwhois = IPWhois(ip_address)
            result = ipwhois.lookup_rdap()
            asn = result.get('asn', 'Unknown')
        except:
            ip_address = "Unknown"
            country = "Unknown"
            asn = "Unknown"
        
        access_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tld = domain.split('.')[-1] if domain else "Unknown"
        
        return {
            "Source URL": source_url,
            "Directed URL": directed_url,
            "IP Address": ip_address,
            "Location": country,
            "Access Date": access_date,
            "TLD": tld,
            "ASN": asn
        }
        
    except requests.Timeout:
        st.error("⚠️ Request timed out while getting URL info")
        return None
    except requests.SSLError:
        st.error("⚠️ SSL verification failed. The website might be using an invalid certificate.")
        return None
    except requests.RequestException as e:
        st.error(f"⚠️ Error accessing URL: {str(e)}")
        return None
    except Exception as e:
        st.error(f"⚠️ Error getting URL info: {str(e)}")
        return None

def analyze_url(url):
    try:
        features = features_extraction.main(url)
        prediction = test.get_prediction_from_url(url, features)
        
        # Đảm bảo prediction là integer
        if prediction is not None:
            prediction = int(prediction)
        
        # Mapping các giá trị feature với mô tả
        feature_names = [
            "Having IP address",
            "URL Length", 
            "URL Shortening service",
            "Having @ symbol",
            "Having double slash",
            "Having dash symbol(Prefix Suffix)",
            "Having multiple subdomains",
            "SSL Final State",
            "Domain Registration Length",
            "Favicon",
            "Port", 
            "HTTPS token in domain name",
            "Request URL",
            "URL of Anchor",
            "Links in tags",
            "SFH",
            "Submitting to email",
            "Abnormal URL",
            "Redirect",
            "On Mouseover",
            "RightClick",
            "PopUpWindow",
            "Iframe",
            "Age of Domain",
            "DNS Record",
            "Web Traffic",
            "Page Rank",
            "Google Index",
            "Links Pointing to Page",
            "Statistical Reports"
        ]

        # Mapping các giá trị -1, 0, 1 với mô tả dễ hiểu
        feature_values = {
            -1: "Phishing",
            0: "Suspicious",
            1: "Legitimate"
        }
        # Tạo 2 cột cho screenshot và URL info
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Website Screenshot")
            screenshot_path = get_screenshot(url)
            if screenshot_path:
                st.image(screenshot_path, use_container_width=True)
        
        with col2:
            st.subheader("URL Information")
            url_info = get_url_info(url)
            if url_info:
                for key, value in url_info.items():
                    st.markdown(f"**{key}:** {value}")
        
        # Hiển thị kết quả phân tích chi tiết
        st.header("Detailed Analysis")
        
        # Tạo 3 cột để phân loại các features
        col1, col2, col3 = st.columns(3)
        
        for idx, (name, value) in enumerate(zip(feature_names, features)):
            status = feature_values[value]
            color = "red" if value == -1 else "orange" if value == 0 else "green"
            
            # Phân phối các features vào 3 cột
            if idx % 3 == 0:
                with col1:
                    st.markdown(f"**{name}**: <span style='color:{color}'>{status}</span>", unsafe_allow_html=True)
            elif idx % 3 == 1:
                with col2:
                    st.markdown(f"**{name}**: <span style='color:{color}'>{status}</span>", unsafe_allow_html=True)
            else:
                with col3:
                    st.markdown(f"**{name}**: <span style='color:{color}'>{status}</span>", unsafe_allow_html=True)

        # Hiển thị kết quả cuối cùng
        st.header("Final Result")
        if prediction == 1:
            st.success("✅ This URL appears to be SAFE")
        elif prediction == -1:
            st.error("⚠️ WARNING: This URL appears to be PHISHING")
        else:
            st.warning("⚠️ This URL appears to be SUSPICIOUS")
            
    except Exception as e:
        st.error(f"An error occurred while analyzing the URL: {str(e)}")

def main():
    st.set_page_config(
        page_title="Malicious URL Detector",
        page_icon="🔍",
        layout="wide"
    )
    
    # Custom CSS
    st.markdown("""
        <style>
        .stTextInput > div > div > input {
            font-size: 20px;
        }
        .main {
            padding: 2rem;
        }
        </style>
    """, unsafe_allow_html=True)

    # Header
    st.title("🔍 Malicious URL Detection")
    st.markdown("""
        This tool helps you detect potentially malicious URLs using machine learning.
        Enter a URL below to analyze its safety.
    """)
    
    # Input URL
    url = st.text_input("Enter the URL to analyze:", placeholder="https://example.com")
    
    # Analyze button
    if st.button("Analyze URL", type="primary"):
        if url:
            with st.spinner("Analyzing URL..."):
                analyze_url(url)
        else:
            st.warning("Please enter a URL")

if __name__ == "__main__":
    main() 