def shout(data):
    data['type'] = 'shout'
    return data


def proto_page(uri, pubkey, guid, text, signature, nickname, PGPPubKey, email,
               bitmessage, arbiter, notary, notary_description, notary_fee,
               arbiter_description, sin, homepage, avatar_url):
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
        'notary_description': notary_description,
        'notary_fee': notary_fee,
        'arbiter_description': arbiter_description,
        'sin': sin,
        'homepage': homepage,
        'avatar_url': avatar_url
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
