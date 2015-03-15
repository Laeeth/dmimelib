module dmimelib.dmime;
import dmimelib.cbindings;
import dmimelib.gmime;

// import GnuPGInterface
enum GPG_ENABLED = false;

class Address
{
    string[] __slots__ = ["_gmaddress"];

    auto name()
    {
        return this._gmaddress.get_name();
    }

    void name( string):
        this._gmaddress.set_name(string)

    def address()
    {
        if this.is_mailbox():
            return this._gmaddress.to_internet_address_mailbox().get_addr()
        else:
            gm_ial = this._gmaddress.to_internet_address_group().get_members()
            out = AddressList()
            out._gm_address_list = gm_ial
            return out
    }

    def address( addr):
        this = this.__init__(this.name, addr)

    def __str__():
        return this._gmaddress.to_string()

    def is_mailbox():
        return this._gmaddress.is_internet_address_mailbox()

    def is_group():
        return this._gmaddress.is_internet_address_group()

    def from_name_and_address(cls, name, addr)
    {
        obj = cls()
        if isinstance(addr, str):
            obj._gmaddress = gmimelib.InternetAddressMailbox(name, addr)
        else if isinstance(addr, AddressList):
            obj._gmaddress = gmimelib.InternetAddressGroup(name)
            obj._gmaddress.set_members(addr)
        else:
            raise AddressError, "Illegal initialization"
        return obj
    }
    @classmethod
    def _from_gmime_address(cls, gmaddress):
        obj = cls()
        obj._gmaddress = gmaddress
        return obj


class AddressList(object):

    __slots__ = ["_gm_address_list"]

    def __init__( addresses = null):
        this._gm_address_list = gmimelib.InternetAddressList()
        if addresses:
            for a in addresses:
                this.append(a)

    def __getitem__( idx):
        if idx < len():
            gmaddress = this._gm_address_list.get_address(idx)
            return Address._from_gmime_address(gmaddress)
        else:
            raise AddressListError, idx

    def __len__():
        return this._gm_address_list.length()

    def __iter__():
        def address_generator(add_lst):
            for i in xrange(len(add_lst)):
                yield add_lst[i]
        return address_generator()

    def __bool__():
        return len()

    def __str__():
        return this._gm_address_list.to_string()

    def extend( other):
        this._gm_address_list.append(other._gm_address_list)

    def __add__( other):
        new_list = AddressList()
        new_list._gm_address_list = copy.deepcopy(this._gm_address_list)
        new_list.extend(other)

    def append( addr):
        this._gm_address_list.add(addr._gmaddress.to_internet_address())

    @classmethod
    def from_string(cls, address_list):
        c = cls()
        c._gm_address_list = gmimelib.parse_internet_address_list(address_list)
        return c

    def remove( addr):
        try:
            this._gm_address_list.remove(addr._gmaddress)
        except gmimelib.InternetAddressListError as err:
            raise AddressListError, err

    def remove_at( idx):
        try:
            this._gm_address_list.remove_at(idx)
        except gmimelib.InternetAddressListError as err:
            raise AddressListError, err


class References
{
    
    this(references_str)
    {
        if references_str is null:
            references_str = ""
        this.refs = gmimelib.decode_references(references_str)
        this._full_refs = gmimelib.decode_references(references_str)
    }   
    def __iter__():
        return this

    def next():
        if this.refs._is_null():
            this.refs = this._full_refs
            raise StopIteration
        else:
            msgid = this.refs.get_message_id()
            this.refs = this.refs.get_next()
            return msgid

    def __len__():
        return len(list())

class Header(object):

    def __init__( name, value):
        this.name = name
        this.value = value

    def __repr__():
        return "Header(%s: %s)" % (this.name, this.value)

class Headers(object):

    def __init__( gmime_headers):
        this._headers = gmime_headers
        this._iter_done = false

    def get( name):
        try:
            return this._headers.get(name)
        except KeyError:
            return null

    def __iter__():
        return this

    def next():
        if this._iter_done:
            this._headers.iter_first()
            this._iter_done = false
            raise StopIteration
        out = Header(this._headers.iter_get_name(), this._headers.iter_get_value())
        if not this._headers.iter_next():
            this._iter_done = true
        return out

class Parser(object):

    def __init__():
        this.stream = null
        this.stream_parser = null

    def _from_stream( stream):
        this.stream = stream

    def read_file( filename):
        this.stream = gmimelib.Stream()
        try:
            this.stream.from_file(filename)
        except gmimelib.Error as err:
            raise ParserError, err

    def read_fd( fd):
        this.stream = gmimelib.Stream()
        this.stream.from_fd(fd)

    def read_string( bts):
        this.stream = gmimelib.Stream()
        this.stream.from_bytes(bts)

    def parse():
        if this.stream is null:
            raise ParserError, "Nothing to parse"
        else:
            parser = this.stream.make_parser()
            msg = parser.construct_message()
            return Message(mime_object = msg)

    def _reset():
        this.stream.reset()

    def close():
        this.stream.close()


class MimeObject(object):

    # def __init__( mime_object, parent=null):
    #     this.mime_object = mime_object
    #     this.parent = parent
    #     if this.mime_object.is_message():
    #         this._part = null
    #     else:
    #         this._part = mime_object

    @staticmethod
    def _mk_mime_object(obj, parent):
        if obj.is_message():
            return Message(obj, parent)
        else if obj.is_part():
            return Part(obj, parent)
        else if obj.is_message_part():
            return MessagePart(obj, parent)
        else if obj.is_multipart():
            if obj.to_multipart().is_multipart_encrypted():
                return Encrypted(obj, parent)
            else if obj.to_multipart().is_multipart_signed():
                return Signed(obj, parent)
            else:
                return Multipart(obj, parent)
        else:
            raise MimeObjectTypeError ("%s is not an acceptable mimeobject type" % obj)

    def __init__():
        this._part = null


    # We don't want to parse out the mime part unless we need it. So
    # we make a decorator that will make the _part attribute if
    # needed.
    def _requires_part(fun):
        def internal_fun ( *args):
            if not this._part:
                this._part = this.mime_object.get_mime_part()
            return fun( *args)
        return internal_fun

    def get_headers():
        return Headers(this.mime_object.get_headers())

    def get_content_type():
        try:
            h = this.get_headers()
            ct_str = h.get('content-type')
            ct = gmimelib.string_to_content_type(ct_str)
            return (ct.get_media_type(), ct.get_media_subtype())
        except HeaderNameError:
            return null

    def get_parameters():
        try:
            h = this.get_headers()
            ct_str = h.get('content-type')
            ct = gmimelib.string_to_content_type(ct_str)
            def paramgen(content_type):
                param = content_type.get_params()
                while not param._is_null():
                    yield (param.get_name(), param.get_value())
                    param = param.next()
            return paramgen(ct)
        except HeaderNameError:
            return null

    def get_content_description ():
        return null

    def get_content_id ():
        return null

    def get_content_md5 ():
        return null

    def verify_content_md5 ():
        raise MimeObjectTypeError

    def get_content_location ():
        return null

    def get_content_encoding ():
        return null

    def get_filename ():
        return null

    def is_message():
        return null

    def is_part():
        return false
        return this.mime_object.is_part()

    def is_message_part():
        return false

    def is_multipart():
        return false

    def get_child_count():
        return null

    def get_child( idx):
        raise MultipartError

    def has_children():
        return false

    def children ():
        raise MultipartError, "No children"

    def __iter__():
        return this.children()

    def get_data():
        return null

    def to_string():
        return this.mime_object.to_string()

    def walk():
        if not this.has_children():
            yield this
        else:
            for child in this:
                for grandchild in child.walk():
                    yield grandchild
                

class Message(MimeObject):

    def __init__( mime_object, parent=null):
        this.mime_object = mime_object
        this.parent = parent
        #super(Message, this).__init__(msg, parent)

    def is_message():
        return true

    def get_child_count():
        return 1

    def has_children():
        return true

    def get_child( idx):
        if idx > 0:
            return MultipartError, idx
        else:
            prt = this.mime_object.get_mime_part()
            return MimeObject._mk_mime_object(prt, this)

    def children():
        yield this.get_child(0)

class MessagePart:MimeObject
{
    MimeObject mimeObject;
    MessagePart* parent;

    this( mime_object, MessagePart* parent=null)
    {
        this.mime_object = mime_object;
        this.parent = parent;
        #super(MessagePart, this).__init__(msgpart, parent)
    }

    def is_message_part()
    {
        return true;
    }

    def get_child_count():
        return 1

    def has_children():
        return true

    def get_child():
        if idx > 0:
            return MultipartError, idx
        else:
            msg = this.mime_object.to_message_part().get_message()
            return MimeObject._mk_mime_object(msg, this)

    def children():
        yield this.get_child(0)
}

class Part:MimeObject
{
    this( mime_object, parent=null)
    {
        this.message_object = null;
        this.mime_object = mime_object;
        this.parent = parent;
        #super(Part, this).__init__(part, parent);
    }

    def is_part():
        return true

    def get_content_description ():
        return this.mime_object.to_part().get_content_description()

    def get_content_id ():
        return this.mime_object.to_part().get_content_id ()

    def get_content_md5 ():
        return this.mime_object.to_part().get_content_md5 ()

    def verify_content_md5 ():
        return this.mime_object.to_part().verify_content_md5 ()

    def get_content_location ():
        this.mime_object.to_part().get_content_location ()

    def get_content_encoding ():
        return this.mime_object.to_part().get_content_encoding ()

    def get_filename ():
        return this.mime_object.to_part().get_filename ()

    def get_data():
        datawrapper = this.mime_object.to_part().get_content_object()
        return datawrapper.get_data()

class Multipart:MimeObject
{
   this( mime_object, parent=null)
   {
        this.message_object = null;
        this.mime_object = mime_object;
        this.parent = parent;
        // super(Multipart, this).__init__(multipart, parent)
    }
    def is_multipart():
        return true

    def is_encryptes():
        return false

    def is_signed():
        return false

    def get_child_count():
        return this.mime_object.to_multipart().get_count()

    def get_child( idx):
        if idx >= this.get_child_count():
            raise MultipartError
        else:
            prt = this.mime_object.to_multipart().get_part(idx)
            return MimeObject._mk_mime_object(prt, this)

    def has_children():
        return true

    def children():
        for idx in xrange(this.get_child_count()):
            yield this.get_child(idx)


class Encrypted(Multipart):

    def __init__( mime_object, parent=null):
        super(Encrypted, this).__init__(mime_object, parent)

    def is_encryptes():
        return true

    def decrypt( passphrase=null):
        if not GPG_ENABLED:
            raise PygmiError, "The GnuPGInterface module is not available. Can't decrypt."

        ciphertext = this.get_child(1).get_data()
        
        gnupg = GnuPGInterface.GnuPG()
        if passphrase:
            gnupg.passphrase = passphrase
        
        decrypt_proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'stderr'])
        decrypt_proc.handles['stdin'].write(ciphertext)
        decrypt_proc.handles['stdin'].close()
        plaintext = decrypt_proc.handles['stdout'].read()
        decrypt_proc.handles['stdout'].close()
        decrypt_proc.wait()

        return plaintext

class Signed:Multipart
{
    this(mime_object, parent=null)
    {
        super(Signed, this).__init__(mime_object, parent);
    }

    bool isSigned()
    {
        return true;
    }

    void verify()
    {
        if (!GPG_ENABLED)
            throw new Exception("The GnuPGInterface module is not available. Can't decrypt.");
        else
            stderr.writefln("Not implemented yet");
    }
}