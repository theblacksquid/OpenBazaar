def shout(data):
    data['type'] = 'shout'
    return data


def proto_page(uri, pubkey, guid, text, signature, nickname, PGPPubKey, email,
               bitmessage, arbiter, notary, arbiter_description, sin, homepage):
    data = {
        'type': 'page',
        'uri': uri,
        'pubkey': pubkey,
        'senderGUID': guid,
        'text': text,
        'nickname': nickname,
        'PGPPubKey': PGPPubKey,
        'email': email,
        'bitmessage': bitmessage,
        'arbiter': arbiter,
        'notary': notary,
        'arbiter_description': arbiter_description,
        'sin': sin,
        'homepage': homepage
    }
    return data


def query_page(guid):
    data = {'type': 'query_page', 'findGUID': guid}
    return data


def proto_store(key, value, originalPublisherID, age):
    data = {
        'type': 'store',
        'key': key,
        'value': value,
        'originalPublisherID': originalPublisherID,
        'age': age
    }
    return data
