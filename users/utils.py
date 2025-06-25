import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

def fetch_school_logo(school_name):
    """
    Fetches a school logo using Google Custom Search API.
    Returns the URL of the first image result or None if no results found.
    """
    try:
        # Construct the search query
        query = f"{school_name} logo"
        logger.info(f"Searching for logo with query: {query}")
        
        # Make the API request
        url = f"https://www.googleapis.com/customsearch/v1"
        params = {
            'q': query,
            'key': settings.GOOGLE_API_KEY,
            'cx': settings.GOOGLE_CSE_ID,
            'searchType': 'image',
            'imgSize': 'medium',
            'num': 1
        }
        
        logger.info(f"Making API request to: {url}")
        response = requests.get(url, params=params)
        logger.info(f"API response status code: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"API request failed with status code: {response.status_code}")
            logger.error(f"Response content: {response.text}")
            return None
            
        data = response.json()
        
        # Check if we have any results
        if 'items' not in data or not data['items']:
            logger.warning(f"No image results found for query: {query}")
            return None
            
        # Get the first image result
        first_result = data['items'][0]
        image_url = first_result.get('link')
        
        if not image_url:
            logger.warning("No image URL found in the first result")
            return None
            
        logger.info(f"Found image URL: {image_url}")
        return image_url
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making API request: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in fetch_school_logo: {str(e)}")
        return None 