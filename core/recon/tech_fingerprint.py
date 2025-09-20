import requests
from urllib.parse import urljoin

def get_technologies(url):
    """
    Performs basic technology fingerprinting on a given URL by analyzing HTTP headers and HTML content.
    """
    technologies = set()
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status()

        # 1. Analyze HTTP Headers
        headers = response.headers
        if 'Server' in headers:
            technologies.add(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            technologies.add(f"X-Powered-By: {headers['X-Powered-By']}")
        if 'Set-Cookie' in headers:
            if 'wordpress' in headers['Set-Cookie'].lower():
                technologies.add("CMS: WordPress (via cookie)")
            if 'laravel_session' in headers['Set-Cookie'].lower():
                technologies.add("Framework: Laravel (via cookie)")
        
        # 2. Analyze HTML Content (first 10KB for efficiency)
        content = response.text[:10240].lower() # Read first 10KB
        
        if "<meta name=\"generator\" content=\"wordpress" in content:
            technologies.add("CMS: WordPress (via meta tag)")
        if "<meta name=\"generator\" content=\"joomla" in content:
            technologies.add("CMS: Joomla (via meta tag)")
        if "<script src=\"/wp-includes/" in content or "wp-content" in content:
            technologies.add("CMS: WordPress (via script/content path)")
        if "react-root" in content or "data-reactroot" in content:
            technologies.add("Frontend: React")
        if "vue.js" in content:
            technologies.add("Frontend: Vue.js")
        if "angular.js" in content:
            technologies.add("Frontend: Angular.js")
        if "jquery" in content:
            technologies.add("Library: jQuery")
        
    except requests.exceptions.RequestException as e:
        # print(f"Error fingerprinting {url}: {e}") # Rich will handle this
        pass
    except Exception as e:
        # print(f"An unexpected error occurred during fingerprinting {url}: {e}") # Rich will handle this
        pass

    return sorted(list(technologies))

if __name__ == '__main__':
    # Example usage
    test_urls = ["https://wordpress.com", "https://react.dev", "https://www.google.com"]
    for url in test_urls:
        print(f"\nFingerprinting {url}...")
        found_tech = get_technologies(url)
        if found_tech:
            for tech in found_tech:
                print(f"    - {tech}")
        else:
            print("    No technologies identified.")
