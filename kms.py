
def create_key_ring(project_id, location_id, key_ring_id):
    """
    Creates a new key ring in Cloud KMS

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the key ring to create (e.g. 'my-key-ring').

    Returns:
        KeyRing: Cloud KMS key ring.

    """

    # Import the client library.
    from google.cloud import kms

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the parent location name.
    location_name = 'projects/{project_id}/locations/{location_id}'

    # Build the key ring.
    key_ring = {}

    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    _key_ring = client.get_key_ring(name=key_ring_name)

    if not (_key_ring is not None and _key_ring.name is not None):
        # Call the API.
        created_key_ring = client.create_key_ring(
            request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})
        print('Created key ring: {}'.format(created_key_ring.name))
        return created_key_ring
    else:
        print('Existed key ring: {}'.format(_key_ring.name))
        return _key_ring 
	
def create_key_hsm(project_id, location_id, key_ring_id, key_id):
    """
    Creates a new key in Cloud KMS backed by Cloud HSM.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to create (e.g. 'my-hsm-key').

    Returns:
        CryptoKey: Cloud KMS key.

    """

    # Import the client library.
    from google.cloud import kms
    from google.protobuf import duration_pb2
    import datetime

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the parent key ring name.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Build the key.
    purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    protection_level = kms.ProtectionLevel.HSM
    key = {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
            'protection_level': protection_level
        },

        # Optional: customize how long key versions should be kept before
        # destroying.
        'destroy_scheduled_duration': duration_pb2.Duration().FromTimedelta(datetime.timedelta(days=1))
    }

    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id,key_id)

    _crypto_key = client.get_crypto_key(name=crypto_key_name)

    if not (_crypto_key is not None and _crypto_key.name is not None):
        # Call the API.
        created_key = client.create_crypto_key(
            request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
        print('Created hsm key: {}'.format(created_key.name))
        return created_key
    else:
        print('Existed crypto key: {}'.format(_crypto_key.name))
        return _crypto_key 


def openssl_rand_32_base64():
    from secrets import token_bytes
    from base64 import b64encode
    return b64encode(token_bytes(32)).decode()


def wrap_key(project_id, location_id, key_ring_id, key_id, plaintext):
    # Import the client library.
    from google.cloud import kms
    from google.protobuf import duration_pb2
    import datetime

    # Create the client.
    client = kms.KeyManagementServiceClient()

    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    response = client.encrypt(name=crypto_key_name, plaintext=plaintext)

    from base64 import b64encode
    wrap_key = b64encode(response.ciphertext)

    return wrap_key


def dlp(project_id):
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client.
    dlp_client = google.cloud.dlp_v2.DlpServiceClient()

    # The string to inspect
    content = "Robert Frost"

    # Construct the item to inspect.
    item = {"value": content}

    # The info types to search for in the content. Required.
    info_types = [{"name": "FIRST_NAME"}, {"name": "LAST_NAME"}]

    # The minimum likelihood to constitute a match. Optional.
    min_likelihood = google.cloud.dlp_v2.Likelihood.POSSIBLE

    # The maximum number of findings to report (0 = server maximum). Optional.
    max_findings = 0

    # Whether to include the matching string in the results. Optional.
    include_quote = True

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        "info_types": info_types,
        "min_likelihood": min_likelihood,
        "include_quote": include_quote,
        "limits": {"max_findings_per_request": max_findings},
    }

    # Convert the project id into a full resource id.
    parent = f"projects/{project_id}"

    # Call the API.
    response = dlp_client.inspect_content(
        request={"parent": parent, "inspect_config": inspect_config, "item": item}
    )

    # Print out the results.
    if response.result.findings:
        for finding in response.result.findings:
            try:
                print("Quote: {}".format(finding.quote))
            except AttributeError:
                pass
            print("Info type: {}".format(finding.info_type.name))
            # Convert likelihood value to string respresentation.
            likelihood = finding.likelihood.name
            print("Likelihood: {}".format(likelihood))
    else:
        print("No findings.")    


def dlp_get_inspectTemplate():
    return None


def dlp_get_deidentify_template(project_id, location_id, deidentify_template_id):
    from google.cloud import dlp_v2
    # Create a client
    client = dlp_v2.DlpServiceClient()
    
    full_resource_name='projects/'+project_id+'/locations/'+location_id+'/deidentifyTemplates/'+deidentify_template_id

    # deidentify_template_name = client.deidentify_template_path(project_id, location_id, deidentify_template_id)
    # Initialize request argument(s)
    request = dlp_v2.GetDeidentifyTemplateRequest(
        name=full_resource_name
    )

    # Make the request
    response = client.get_deidentify_template(request=request)

    # Handle the response
    # print(response)
    return response

def dlp_update_deidentify_template_wrapped_key(project_id, location_id, deidentify_template_id, crypto_key_name, wrapped_key, surrogate_info_type):
    from google.cloud import dlp_v2
    from google.protobuf import field_mask_pb2
    from base64 import b64decode
    # Create a client
    client = dlp_v2.DlpServiceClient()
    
    full_resource_name='projects/'+project_id+'/locations/'+location_id+'/deidentifyTemplates/'+deidentify_template_id

    _update_mask = field_mask_pb2.FieldMask(paths=['deidentify_config'])

    _deidentify_template=dlp_get_deidentify_template(project_id, location_id, deidentify_template_id)

    _deidentify_template.deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {
                    "primitive_transformation": {
                        "crypto_deterministic_config": {
                            "crypto_key": {
                                "kms_wrapped": {
                                    "wrapped_key":b64decode(wrapped_key),
                                    "crypto_key_name":crypto_key_name
                                }
                            },
                            "surrogate_info_type": {
                                "name":surrogate_info_type
                            }
                        }                                                
                    }
                }
            ]
        }
    }
     
    request = dlp_v2.UpdateDeidentifyTemplateRequest(
        name=full_resource_name,
        deidentify_template=_deidentify_template,
        update_mask=_update_mask
    )

    # Make the request
    response = client.update_deidentify_template(request=request)

    # Handle the response
    # print(response)
    return response


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    project_id='xxxx'
    location_id='global'
    key_ring_id='my-key-ring'
    key_id='my-hsm-key'
    deidentify_template_id='deTest'

    crypto_key_ring_name=create_key_ring(project_id,location_id,key_ring_id).name
    print("crypto_key_ring_name:",crypto_key_ring_name)
    crypto_key_name=create_key_hsm(project_id,location_id,key_ring_id,key_id).name
    print("crypto_key_name:",crypto_key_name)

    openssl_key_b64 = openssl_rand_32_base64()
    print("openssl_key_b64:",openssl_key_b64)

    from base64 import b64decode
    print("openssl_key_b64 binary:", b64decode(openssl_key_b64))

    wrapped_key = wrap_key(project_id,location_id,key_ring_id,key_id, openssl_key_b64)
    print(wrapped_key)

    surrogate_info_type="siTestNew001"
    response=dlp_update_deidentify_template_wrapped_key(project_id,location_id, deidentify_template_id, crypto_key_name, wrapped_key, surrogate_info_type)
    print(response)

    #dlp_get_deidentify_template(project_id,location_id, deidentify_template_id)