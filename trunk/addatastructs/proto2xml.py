import base64
from xml.sax.saxutils import escape

def proto2xml(message, descriptor=None, indent=None):
    def dovalue(val):
        if desc.message_type is not None:
            output = proto2xml(val,desc,None if indent is None else indent+1)
        else:
            valtag = desc.name
            valtype = desc.type
            if valtype == desc.TYPE_BYTES:
                valstr = base64.b64encode(val)
            elif valtype == desc.TYPE_STRING:
                valstr = escape(val)
            else:
                valstr = str(val)
            output = ''
            if indent:
                output += '\t'*(indent+1)
            output += '<'+valtag+'>' + valstr + '</'+valtag+'>'
            if indent is not None:
                output += '\n'
        return output

    attribute_names = ['resultitemtype']
    suboutput = ''
    attributes = {}
    for desc,value in message.ListFields():
        if desc.label == desc.LABEL_REPEATED:
            for val in value:
                suboutput += dovalue(val)
        elif desc.name in attribute_names:
            attributes[desc.name] = str(value)
        else:
            suboutput += dovalue(value)

    if descriptor:
        tag = descriptor.name
    else:
        tag = message.DESCRIPTOR.name
        if tag[-4:] == 'Type':
            tag = tag[:-4]
    output = ''
    if indent:
        output += '\t'*indent
    output += '<'+tag
    for name,value in attributes.iteritems():
        output += ' '+name+'="'+value+'"'
    output += '>'
    if indent is not None:
        output += '\n'
    output += suboutput
    if indent:
        output += '\t'*indent
    output += '</'+tag+'>'
    if indent is not None:
        output += '\n'
    return output


if __name__ == '__main__':
    from processors_pb2 import *
    message = rootType()
    message.ParseFromString(open(r'\svn\volatility\processors.pb2').read())
    print proto2xml(message,indent=0)