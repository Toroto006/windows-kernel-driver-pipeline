# coding=utf8
import re
import json

def extract_signer_info(sigcheck_output):
    sginatures = []
    # scan linearly for correct start and then based on indentation]
    sign_catalog_regex = r"\s*Signing date:\s+(.*)\s+Catalog:\s+(.*)\s+Signers?:\n"
    signer_regex = r"\n\s+(.*)\s+Cert Status:\s+(.*)\s+Valid Usage:\s+(.*)\s+Cert Issuer:\s+(.*)\s+Serial Number:\s+(.*)\s+Thumbprint:\s+(.*)\s+Algorithm:\s+(.*)\s+Valid from:\s+(.*)\s+Valid to:\s+(.*)"
    lines = sigcheck_output.splitlines()

    start_indices = [idx for idx, line in enumerate(lines) if "Signing date:" in line]
    end_indices = [idx for idx, line in enumerate(lines) if "Signing date:" in line or "Company:" in line][1:]
    counter_signer_indices = [idx for idx, line in enumerate(lines) if "Counter Signers:" in line]
    if len(counter_signer_indices) == 0 and len(start_indices) == len(end_indices):
        print("No counter signers")
        counter_signer_indices = end_indices
    elif len(start_indices) != len(end_indices) or len(start_indices) != len(counter_signer_indices):
        raise Exception("Mismatch in start, end, counter signer indices for extract signer info!: ", start_indices, end_indices, counter_signer_indices)

    revoked_signatures = []
    for start, end, cnt_idx in zip(start_indices, end_indices, counter_signer_indices):
        sign_cat = re.search(sign_catalog_regex, '\n'.join(lines[start:end+1]), re.MULTILINE)
        signature = {}
        if sign_cat is None:
            # no catalog and signers probably
            # get only the possible signing date
            sign_date = re.search(r"\s*Signing date:\s+(.*)", lines[start], re.MULTILINE)
            if sign_date is None:
                raise Exception("No match found for the signing date regex?!?")
            
            signature = {
                "Signing date": sign_date.group(1),
                "Catalog": "n/a",
            }
        else:
            signature = {
                "Signing date": sign_cat.group(1),
                "Catalog": sign_cat.group(2)
            }

        signers = []
        cnt_signers = []

        revoked_signer = False
        for signer in re.finditer(signer_regex, '\n'.join(lines[start:cnt_idx+1]), re.MULTILINE):
            signers.append({
                "Signer": signer.group(1),
                "Cert Status": signer.group(2),
                #"Valid Usage": signer.group(3),
                "Cert Issuer": signer.group(4),
                #"Serial Number": signer.group(5),
                #"Thumbprint": signer.group(6),
                #"Algorithm": signer.group(7),
                "Valid from": signer.group(8),
                "Valid to": signer.group(9)
            })
            if not revoked_signer and "certificate chain has been revoked." in signer.group(2):
                revoked_signer = True
        signature.update({"Signers": signers})

        for cnt_signer in re.finditer(signer_regex, '\n'.join(lines[cnt_idx:end+1]), re.MULTILINE):
            cnt_signers.append({
                "Signer": cnt_signer.group(1),
                "Cert Status": cnt_signer.group(2),
                #"Valid Usage": cnt_signer.group(3),
                "Cert Issuer": cnt_signer.group(4),
                #"Serial Number": cnt_signer.group(5),
                #"Thumbprint": cnt_signer.group(6),
                #"Algorithm": cnt_signer.group(7),
                "Valid from": cnt_signer.group(8),
                "Valid to": cnt_signer.group(9)
            })
        signature.update({"Counter Signers": cnt_signers})

        sginatures.append(signature)
        if revoked_signer:
            revoked_signatures.append(revoked_signer)

    return {"Signatures": sginatures}, len(revoked_signatures) > 0 and len(revoked_signatures) == len(sginatures)

def extract_specific_content(output):
    end_regex = r"Company:\s+(.*)\s+Description:\s+(.*)\s+Product:\s+(.*)\s+Prod version:\s+(.*)\s+File version:\s+(.*)\s+MachineType:\s+(.*)\s+MD5:\s+(.*)\s+SHA1:\s+(.*)\s+PESHA1:\s+(.*)\s+PE256:\s+(.*)\s+SHA256:\s+(.*)\s+IMP:\s+(.*)"
    match = re.search(end_regex, output, re.MULTILINE)
    if match:
        return {
            "Company": match.group(1),
            "Description": match.group(2),
            "Product": match.group(3),
            "Prod version": match.group(4),
            "File version": match.group(5),
            #"MachineType": match.group(6),
            #"MD5": match.group(7),
            #"SHA1": match.group(8),
            #"PESHA1": match.group(9),
            #"PE256": match.group(10),
            "SHA256": match.group(11),
            #"IMP": match.group(12)
        }
    else:
        raise Exception("No match found for the end regex?!?")

def parse_sigcheck_output(sigcheck_output):
    json_return = {}
    
    verified = re.search(r"Verified:\s+(.*)", sigcheck_output, re.MULTILINE)
    if verified is None:
        raise Exception("No match found for the verified regex?!?")
    json_return.update({"Verified": verified.group(1)})

    try:
        signers_return, revoked = extract_signer_info(sigcheck_output)
        json_return.update(signers_return)
    except Exception as e:
        print("Error in extracting signers: ", e)
        revoked = False
    if "Signed" in json_return["Verified"] and revoked:
        json_return.update({"Verified": "Revoked"})
    
    try:
        json_return.update(extract_specific_content(sigcheck_output))
    except Exception as e:
        print("Error in extracting specific content: ", e)
    return json_return


if __name__ == "__main__":
    # Sample output from sigcheck
    sigcheck_output = ""
    with open('sigcheck.txt', 'r', encoding='UTF-16') as f:
        sigcheck_output = f.read()

    # Parse the output and convert to JSON
    parsed_data = parse_sigcheck_output(sigcheck_output)
    json_output = json.dumps(parsed_data, indent=4)
    print(json_output)
