# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) 2019 Gabriel Potter <gabriel@potter.fr>
# Copyright (C) 2012 Luca Invernizzi <invernizzi.l@gmail.com>
# Copyright (C) 2012 Steeve Barbeau <http://www.sbarbeau.fr>

# This program is published under a GPLv2 license

"""
HTTP 1.0 layer.

Load using:
>>> load_layer("http")
Note that this layer ISN'T loaded by default, as quite experimental for now.

To follow HTTP packets streams = group packets together to get the
whole request/answer, use `TCPSession` as:
>>> sniff(session=TCPSession)  # Live on-the-flow session
>>> sniff(offline="./http_chunk.pcap", session=TCPSession)  # pcap

This will decode HTTP packets using `Content_Length` or chunks,
and will also decompress the packets when needed.
Note: on failure, decompression will be ignored.

You can turn auto-decompression/auto-compression off with:
>>> conf.contribs["http"]["auto_compression"] = True
"""

# This file is a modified version of the former scapy_http plugin.
# It was reimplemented for scapy 2.4.3+ using sessions, stream handling..
# Original Authors : Steeve Barbeau, Luca Invernizzi
# Originally published under a GPLv2 license

import re

from scapy.compat import plain_str, gzip_compress, gzip_decompress
from scapy.config import conf
from scapy.fields import StrField
from scapy.packet import Packet, bind_layers, Raw

from scapy.layers.inet import TCP
from scapy.modules import six

if "http" not in conf.contribs:
    conf.contribs["http"] = {}
    conf.contribs["http"]["auto_compression"] = True


def _canonicalize_header(name):
    """Takes a header key (i.e., "Host" in "Host: www.google.com",
    and returns a canonical representation of it
    """
    return plain_str(name.strip().lower())


def _parse_headers(s):
    headers = s.split(b"\r\n")
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(b':', 1)
        except ValueError:
            continue
        header_key = _canonicalize_header(key).replace("-", "_")
        headers_found[header_key] = header_line.strip()
    return headers_found


def _parse_headers_and_body(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      _ the first line (e.g., "GET ...")
      _ the headers in a dictionary
      _ the body
    '''
    crlfcrlf = b"\x0d\x0a\x0d\x0a"
    crlfcrlfIndex = s.find(crlfcrlf)
    if crlfcrlfIndex != -1:
        headers = s[:crlfcrlfIndex + len(crlfcrlf)]
        body = s[crlfcrlfIndex + len(crlfcrlf):]
    else:
        headers = s
        body = b''
    first_line, headers = headers.split(b"\r\n", 1)
    return first_line.strip(), _parse_headers(headers), body


def _dissect_headers(obj, s):
    """Takes a HTTP packet as the string s, and populates the scapy layer obj
    (either HTTPResponse or HTTPRequest). Returns the first line of the
    HTTP packet, and the body
    """
    first_line, headers, body = _parse_headers_and_body(s)
    obj.setfieldval('Headers', b'\r\n'.join(list(headers.values())))
    for f in obj.fields_desc:
        canonical_name = _canonicalize_header(f.name)
        try:
            header_line = headers[canonical_name]
        except KeyError:
            continue
        _, value = header_line.split(b':', 1)
        obj.setfieldval(f.name, value.strip())
        del headers[canonical_name]
    return first_line, body


def _get_field_value(obj, name):
    """Returns the value of a packet field."""
    val = obj.getfieldval(name)
    if name != 'Headers':
        return val
    # Headers requires special handling, as we give a parsed
    # representation of it.
    headers = _parse_headers(val)
    val = []
    for header_name in headers:
        try:
            header_value = obj.getfieldval(header_name.capitalize())
            # If we provide a parsed representation for this header
            headers[header_name] = header_value
            val.append(b'%s: %s' % (header_name.capitalize().encode(),
                                    header_value))
        except AttributeError:
            # If we don't provide a parsed representation
            val.append(headers[header_name])
    return b'\r\n'.join(val)


def _self_build(obj, field_pos_list=None):
    ''' Takes an HTTPRequest or HTTPResponse object, and creates its internal
    scapy representation as a string. That is, generates the HTTP
    packet as a string '''
    p = b""
    newline = b'\x0d\x0a'  # '\r\n'
    # Walk all the fields, in order
    for f in obj.fields_desc:
        if f.name not in ['Method', 'Path', 'Status_Line', 'Http_Version',
                          'Headers']:
            # Additional fields added for user-friendliness should be ignored
            continue
        # Get the field value
        val = _get_field_value(obj, f.name)
        # Fields used in the first line have a space as a separator, whereas
        # headers are terminated by a new line
        if f.name in ['Method', 'Path', 'Status_Line']:
            separator = b' '
        else:
            separator = newline
        # Add the field into the packet
        p = f.addfield(obj, p, val + separator)
    # The packet might be empty, and in that case it should stay empty.
    if p:
        # Add an additional line after the last header
        p = f.addfield(obj, p, b'\r\n')
    return p


class _HTTPContent(Packet):
    # https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Transfer-Encoding
    def _get_encodings(self):
        encodings = []
        if self.Transfer_Encoding:
            encodings += [_canonicalize_header(x) for x in
                          plain_str(self.Transfer_Encoding).split(",")]
        if self.Content_Encoding:
            encodings += [_canonicalize_header(x) for x in
                          plain_str(self.Content_Encoding).split(",")]
        return encodings

    def post_dissect(self, s):
        if not conf.contribs["http"]["auto_compression"]:
            return s
        # Decompress
        try:
            encodings = self._get_encodings()
            if "deflate" in encodings:
                import zlib
                s = zlib.decompress(s)
            elif "gzip" in encodings:
                s = gzip_decompress(s)
            elif "compress" in encodings:
                import lzw
                s = lzw.decompress(s)
        except Exception:
            # Cannot decompress - probably incomplete data
            pass
        return s

    def post_build(self, pkt, pay):
        if not conf.contribs["http"]["auto_compression"]:
            return pkt + pay
        # Compress
        encodings = self._get_encodings()
        if "deflate" in encodings:
            import zlib
            pay = zlib.compress(pay)
        elif "gzip" in encodings:
            pay = gzip_compress(pay)
        elif "compress" in encodings:
            import lzw
            pay = lzw.compress(pay)
        return pkt + pay

    def self_build(self, field_pos_list=None):
        """Generate the HTTP packet string (the oppposite of do_dissect)"""
        return _self_build(self, field_pos_list)


class HTTPRequest(_HTTPContent):
    name = "HTTP Request"
    http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
    fields_desc = [StrField("Method", None, fmt="H"),
                   StrField("Path", None, fmt="H"),
                   StrField("Http_Version", None, fmt="H"),
                   StrField("Host", None, fmt="H"),
                   StrField("User_Agent", None, fmt="H"),
                   StrField("Accept", None, fmt="H"),
                   StrField("Accept_Language", None, fmt="H"),
                   StrField("Accept_Encoding", None, fmt="H"),
                   StrField("Accept_Charset", None, fmt="H"),
                   StrField("Referer", None, fmt="H"),
                   StrField("Authorization", None, fmt="H"),
                   StrField("Expect", None, fmt="H"),
                   StrField("From", None, fmt="H"),
                   StrField("If_Match", None, fmt="H"),
                   StrField("If_Modified_Since", None, fmt="H"),
                   StrField("If_None_Match", None, fmt="H"),
                   StrField("If_Range", None, fmt="H"),
                   StrField("If_Unmodified_Since", None, fmt="H"),
                   StrField("Max_Forwards", None, fmt="H"),
                   StrField("Proxy_Authorization", None, fmt="H"),
                   StrField("Range", None, fmt="H"),
                   StrField("TE", None, fmt="H"),
                   StrField("Cache_Control", None, fmt="H"),
                   StrField("Connection", None, fmt="H"),
                   StrField("Date", None, fmt="H"),
                   StrField("Pragma", None, fmt="H"),
                   StrField("Trailer", None, fmt="H"),
                   StrField("Transfer_Encoding", None, fmt="H"),
                   StrField("Upgrade", None, fmt="H"),
                   StrField("Via", None, fmt="H"),
                   StrField("Warning", None, fmt="H"),
                   StrField("Keep_Alive", None, fmt="H"),
                   StrField("Allow", None, fmt="H"),
                   StrField("Content_Encoding", None, fmt="H"),
                   StrField("Content_Language", None, fmt="H"),
                   StrField("Content_Length", None, fmt="H"),
                   StrField("Content_Location", None, fmt="H"),
                   StrField("Content_MD5", None, fmt="H"),
                   StrField("Content_Range", None, fmt="H"),
                   StrField("Content_Type", None, fmt="H"),
                   StrField("Expires", None, fmt="H"),
                   StrField("Last_Modified", None, fmt="H"),
                   StrField("Cookie", None, fmt="H"),
                   StrField("Headers", None, fmt="H")]

    def do_dissect(self, s):
        """From the HTTP packet string, populate the scapy object"""
        first_line, body = _dissect_headers(self, s)
        Method, Path, HTTPVersion = re.split(br"\s+", first_line)
        self.setfieldval('Method', Method)
        self.setfieldval('Path', Path)
        self.setfieldval('Http_Version', HTTPVersion)
        return body


class HTTPResponse(_HTTPContent):
    name = "HTTP Response"
    fields_desc = [StrField("Status_Line", None, fmt="H"),
                   StrField("Accept_Ranges", None, fmt="H"),
                   StrField("Age", None, fmt="H"),
                   StrField("E_Tag", None, fmt="H"),
                   StrField("Location", None, fmt="H"),
                   StrField("Proxy_Authenticate", None, fmt="H"),
                   StrField("Retry_After", None, fmt="H"),
                   StrField("Server", None, fmt="H"),
                   StrField("Vary", None, fmt="H"),
                   StrField("WWW_Authenticate", None, fmt="H"),
                   StrField("Cache_Control", None, fmt="H"),
                   StrField("Connection", None, fmt="H"),
                   StrField("Date", None, fmt="H"),
                   StrField("Pragma", None, fmt="H"),
                   StrField("Trailer", None, fmt="H"),
                   StrField("Transfer_Encoding", None, fmt="H"),
                   StrField("Upgrade", None, fmt="H"),
                   StrField("Via", None, fmt="H"),
                   StrField("Warning", None, fmt="H"),
                   StrField("Keep_Alive", None, fmt="H"),
                   StrField("Allow", None, fmt="H"),
                   StrField("Content_Encoding", None, fmt="H"),
                   StrField("Content_Language", None, fmt="H"),
                   StrField("Content_Length", None, fmt="H"),
                   StrField("Content_Location", None, fmt="H"),
                   StrField("Content_MD5", None, fmt="H"),
                   StrField("Content_Range", None, fmt="H"),
                   StrField("Content_Type", None, fmt="H"),
                   StrField("Expires", None, fmt="H"),
                   StrField("Last_Modified", None, fmt="H"),
                   StrField("Headers", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        self.setfieldval('Status_Line', first_line)
        return body


class HTTP(Packet):
    name = "HTTP"
    fields_desc = []

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and False:
            # XXX TODO
            from scapy.contrib.contrib.http2 import H2Frame
            return H2Frame
        return cls

    # tcp_reassemble is used by TCPSession in session.py
    @classmethod
    def tcp_reassemble(cls, frags, metadata):
        # We need to start with an HTTP
        elt1, header_frag = next(six.iteritems(frags))
        if not isinstance(header_frag[HTTP].payload, _HTTPContent):
            frag = frags[elt1]
            del frags[elt1]
            return frag
        # We have an HTTP packet to start with
        if "process_func" in metadata:
            process_func = metadata["process_func"]
        else:
            # Let's build the end function
            length = header_frag.Content_Length
            if length:
                length = int(length)
                # use Content-Length
                process_func = lambda x, dat: (
                    dat + x,
                    len(dat + x) >= length
                )
            else:
                http_frag_h = header_frag[HTTP].payload
                encodings = http_frag_h._get_encodings()
                chunked = metadata["chunked"] = ("chunked" in encodings)
                if chunked:
                    # Use chunks
                    process_func = lambda x, dat: (
                        dat + x,
                        x == b''
                    )
                else:
                    # Use nothing
                    process_func = lambda x, dat: (
                        dat + x,
                        True
                    )
            # Store it for future usage if needed
            metadata["process_func"] = process_func
        # We have an end function, try to build the packet
        data = b""
        # Look for an end
        processed_seqs = []
        previous_frame = None
        previous_length = None
        results = []
        for i, f in six.iteritems(frags):
            processed_seqs.append(i)
            if HTTP in f:
                pay = f[HTTP].payload
                if i != elt1 and isinstance(pay, _HTTPContent):
                    # Probably missing data, but we need to end now,
                    # because another element starts
                    processed_seqs.remove(i)
                    for k in processed_seqs:
                        results.append(frags[k])
                    processed_seqs = [i]
                    continue
            else:
                # It could also be an extra Raw payload
                pay = f[TCP].payload
            if Raw in pay:
                load = f[Raw].load
                if metadata.get("chunked", False):
                    if previous_frame is not None:
                        length = previous_length
                        body = previous_frame + load
                        previous_frame = None
                        previous_length = None
                    else:
                        length, _, body = load.partition(b"\r\n")
                        try:
                            length = int(length, 16)
                        except ValueError:
                            # Invalid chunk. Probably a retransmission. Ignore
                            results.append(frags[i])
                            del frags[i]
                            continue
                    if len(body) - 2 < length:
                        # Chunk unfinished. Stack up for next frame
                        previous_frame = body
                        previous_length = length
                        continue
                    load = body[:length]
                    if body[length:] != b"\r\n":
                        # Invalid chunk
                        continue
                data, end = process_func(load, data)
                if end:
                    # Proper HTTP data
                    break
            else:
                data, end = process_func(b"", data)
                if end:
                    # Other HTTP packet
                    break
        else:
            # No packet ready yet
            return results
        # Data acquired
        # Build packet
        pkt = header_frag.copy()
        assert isinstance(pkt[HTTP].payload, _HTTPContent)
        decoding_func = pkt[HTTP].payload.post_dissect
        # Process Raw payload
        if data:
            # Process data if not chunked
            if not metadata.get("chunked", False):
                data = decoding_func(data)
            # End packet
            if Raw in pkt:
                pkt[Raw].underlayer.remove_payload()
            pkt = pkt / data
        # Clear frags used in the process
        for i in processed_seqs:
            del frags[i]
        metadata.clear()
        results.append(pkt)
        return results

    def guess_payload_class(self, payload):
        """Decides if the payload is an HTTP Request or Response, or
        something else.
        """
        try:
            prog = re.compile(
                br"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                br"(?:.+?) "
                br"HTTP/\d\.\d$"
            )
            crlfIndex = payload.index(b"\r\n")
            req = payload[:crlfIndex]
            result = prog.match(req)
            if result:
                return HTTPRequest
            else:
                prog = re.compile(br"^HTTP/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return HTTPResponse
        except ValueError:
            # Anything that isn't HTTP but on port 80
            pass
        return Raw


bind_layers(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=80)

# For Proxy
bind_layers(TCP, HTTP, sport=8080)
bind_layers(TCP, HTTP, dport=8080)
