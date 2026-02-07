import requests
from urllib.parse import quote

def test_api():
    API_KEY = "AIzaSyD6Ibt83pVHwua_wByvHtpmPt2JsPJPPkQ"
    CSE_ID = "64ea4b8fcead34b1a"
    query = quote("Hacettepe Üniversitesi logo")
    
    url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={API_KEY}&cx={CSE_ID}&searchType=image&imgSize=medium&num=1"
    
    print(f"Testing API with URL: {url}")
    
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_api() 