import logging
import os
import boto3
from configuration import SETTINGS

LOG = logging.getLogger('{$integration}')

SETTINGS.set_prefix_description('{$prefix}', 'Settings to connect to an AWS S3 bucket')
SETTINGS.create('{$prefix}', {
    'AWS_ACCESS_KEY_ID': '{$access_key}',
    'AWS_SECRET_ACCESS_KEY': '{$secret_key}',
    'AWS_REGION': '{$region}',
    'BUCKET_NAME': '{$bucket}'
})

botocore_log = logging.getLogger('botocore')
botocore_log.setLevel(logging.ERROR)

S3 = boto3.client('s3',
                  aws_access_key_id=SETTINGS['S3_AWS_ACCESS_KEY_ID'],
                  aws_secret_access_key=SETTINGS['S3_AWS_SECRET_ACCESS_KEY'],
                  region_name=SETTINGS['S3_AWS_REGION']
                  )


def cancel_all_pending_uploads(bucket=SETTINGS['S3_BUCKET_NAME']):
    pending_uploads = S3.list_multipart_uploads(Bucket=bucket)
    if 'Uploads' in pending_uploads:
        LOG.info(f'Aborting {len(pending_uploads["Uploads"])} uploads')
        for upload in pending_uploads["Uploads"]:
            upload_id = upload["UploadId"]
            S3.abort_multipart_upload(Bucket=bucket, Key=upload['Key'], UploadId=upload_id)


def file_exists(filename, bucket=SETTINGS['S3_BUCKET_NAME']):
    response = S3.list_objects_v2(Bucket=bucket, Prefix=filename)
    if response:
        for obj in response.get('Contents', {}):
            if filename == obj['Key']:
                return True
    return False


def start_multipart_upload(filename, bucket=SETTINGS['S3_BUCKET_NAME']):
    mpu = S3.create_multipart_upload(Bucket=bucket, Key=filename, ACL='public-read')
    return {
        'mpu': mpu,
        'parts': [],
        'filename': filename,
        'chunk_count': 0
    }


def upload_chunk(upload_context, chunk, chunk_number):
    LOG.debug(f"chunk_number {chunk_number}: {upload_context['mpu']['Bucket']} / "
              f"{upload_context['mpu']['Key']} / {upload_context['mpu']['UploadId']}")

    part = S3.upload_part(
        Bucket=upload_context['mpu']['Bucket'],
        Key=upload_context['mpu']['Key'],
        UploadId=upload_context['mpu']['UploadId'],
        Body=chunk,
        PartNumber=chunk_number
    )
    upload_context['parts'].append({"PartNumber": chunk_number, "ETag": part['ETag']})


def complete_upload(upload_context):
    parts = sorted(upload_context['parts'], key=lambda d: d['PartNumber'])
    result = S3.complete_multipart_upload(
        Bucket=upload_context['mpu']['Bucket'],
        Key=upload_context['mpu']['Key'],
        UploadId=upload_context['mpu']['UploadId'],
        MultipartUpload={'Parts': parts}
    )
    upload_context['href'] = result['Location']


def cancel_pending_upload(upload_context):
    result = S3.abort_multipart_upload(
        Bucket=upload_context['mpu']['Bucket'],
        Key=upload_context['mpu']['Key'],
        UploadId=upload_context['mpu']['UploadId']
    )

    return result


def delete_assets(filename, bucket=SETTINGS['S3_BUCKET_NAME']):
    result = S3.delete_object(Bucket=bucket, Key=filename)
    return result
