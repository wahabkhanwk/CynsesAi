import logging
import json
import mimetypes
import subprocess
from io import BytesIO

import requests
from PIL import Image
from PIL.ExifTags import TAGS

logging.getLogger('PIL').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)


def _get_video_info(href, is_video=True):
    result = subprocess.check_output(f'ffprobe -v quiet -show_streams -select_streams v:0 -of json "{href}"',
                                     shell=True).decode()
    details = json.loads(result)['streams'][0]
    rtn = {
        'width': details['width'],
        'height': details['height'],
        'codec': details['codec_name'],
        'duration': float(details.get('duration', 0.0)),
    }
    if details.get('closed_captions'):
        rtn['closedCaptions'] = True
    if 'tags' in details:
        rtn['tags'] = details['tags']
    if 'nb_frames' in details:
        rtn['frameCount'] = details['nb_frames']

    return rtn


def _get_image_info(href):
    if href.startswith('http://') or href.startswith('https://'):
        response = requests.get(href)
        image = Image.open(BytesIO(response.content))
    else:
        with open(href, 'rb') as file:
            image = Image.open(file)
    rtn = {
        'format': image.format,
        'height': image.height,
        'width': image.width,
        'size': image.size,
    }

    exif = {}
    image_exif = image._getexif()
    if image_exif:
        for (key, val) in image_exif.items():
            exif[TAGS.get(key)] = val

    if exif:
        rtn['exif'] = json.loads(json.dumps(exif, default=str))

    return rtn


def get_metadata(href):
    rtn = {}
    content_type = mimetypes.guess_type(href)[0] if mimetypes.guess_type(href)[0] else 'application/octet-stream'
    major_type = content_type.split('/')[0]

    type_map = {
        'video': _get_video_info,
        'image': _get_image_info
    }

    if major_type in type_map:
        rtn = type_map[major_type](href)
    else:
        response = requests.head(href, allow_redirects=True)
        try:
            size = int(response.headers.get('content-length', -1))
        except ValueError:
            size = -1
        if size >= 0:
            rtn = {'size': size}

    return rtn
