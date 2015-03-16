module dmimelib.dmime;
import dmimelib.cbindings;
import dmimelib.gmime;
import std.format;
import std.string;

// import GnuPGInterface
enum GPG_ENABLED = false;

class Address
{
    string[] __slots__ = ["_gmaddress"];

    auto name()
    {
        return this._gmaddress.get_name();
    }

    void name( string)
    {
        this._gmaddress.set_name(string);
    }

    string address()
    {
        if this.isMailbox()
            return this._gmaddress.to_internet_address_mailbox().get_addr();
        else
        {
            auto gm_ial = this._gmaddress.to_internet_address_group().get_members();
            auto out = AddressList();
            out._gm_address_list = gm_ial;
            return out;
        }
    }

    def address( addr):
        this = this.__init__(this.name, addr)

    def __str__():
        return this._gmaddress._toString()

    def isMailbox():
        return this._gmaddress.is_internet_address_mailbox()

    def isGroup():
        return this._gmaddress.is_internet_address_group()

    def fromNameAndAddress(cls, name, addr)
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


class AddressList
{
    string[] __slots__ = ["_gm_address_list"]

    this( addresses = null)
    {
        this._gm_address_list = gmimelib.InternetAddressList();
        if addresses
        {
            foreach(a;addresses)
                this.append(a);
        }

    private auto __getitem__( idx)
    {
        if (idx < len())
        {
            gmaddress = this._gm_address_list.get_address(idx);
            return Address._from_gmime_address(gmaddress);
        }
        else:
            throw new Exception(AddressListError, idx);
    }

    private auto __len__()
    {
        return this._gm_address_list.length();
    }

    private auto __iter__()
    {
        private address_generator(add_lst)
        {
            foreach(i;0..add_lst.length):
                yield add_lst[i]
        }
        return address_generator()
    }

    private auto __bool__()
    {
        return len();
    }

    private auto  __str__()
    {
       return this._gm_address_list._toString();
    }

    void extend( other)
    {
        this._gm_address_list.append(other._gm_address_list);
    }

    def __add__( other):
        new_list = AddressList()
        new_list._gm_address_list = copy.deepcopy(this._gm_address_list)
        new_list.extend(other)

    void append( addr)
    {
        this._gm_address_list.add(addr._gmaddress.to_internet_address());
    }

    @classmethod
    def from_string(cls, address_list):
        c = cls()
        c._gm_address_list = gmimelib.parse_internet_address_list(address_list)
        return c

    void remove( addr)
    {
        try
        {
            this._gm_address_list.remove(addr._gmaddress);
        }
        except gmimelib.InternetAddressListError as err
            raise AddressListError, err;
    }

    void removeAt( idx)
    {
        try
        {
            this._gm_address_list.remove_at(idx)
        }
        catch Exception e)
        {
            except gmimelib.InternetAddressListError as err
                throw new Exception(AddressListError, err);
        }
    }
}

class References
{
    
    this(references_str)
    {
        if references_str is null:
            references_str = ""
        this.refs = gmimelib.decode_references(references_str)
        this._full_refs = gmimelib.decode_references(references_str)
    }   

    private auto  __iter__()
    {
        return this
    }

    auto next()
    {
        if (this.refs._is_null())
        {
            this.refs = this._full_refs;
            raise StopIteration;
        }
        else
        {
            msgid = this.refs.get_message_id();
            this.refs = this.refs.get_next();
            return msgid;
        }
    }

    private auto __len__()
    {
        return list.length;
    }
}
class Header
{
    string name;
    string value;

    def __init__( name, value)
    {
        this.name = name;
        this.value = value;
    }

    string toString()
    {
        return format("Header(%s: %s)",this.name, this.value);
    }
}

class Headers
{
    this( gmime_headers)
    {
        this._headers = gmime_headers;
        this._iter_done = false;
    }

    auto get( name)
    {
        try:
            return this._headers.get(name);
        except KeyError
            return null;
    }

    private auto  __iter__()
    {
        return this;
    }

    auto next()
    {
        if this._iter_done
        {
            this._headers.iter_first();
            this._iter_done = false;
            raise StopIteration;
        }
        auto _out = Header(this._headers.iter_get_name(), this._headers.iter_get_value());
        if (not this._headers.iter_next())
            this._iter_done = true;
        return _out;
    }
}

class Parser
{
    this()
    {
        this.stream = null;
        this.stream_parser = null;
    }

    this(stream)
    {
        this.stream = stream
        this.stream_parser = null;
    }

    def readFile( filename)
    {
        this.stream = gmimelib.Stream();
        try
        {
            this.stream.from_file(filename);
        }
        catch(gmimelibException e)
        {
            throw new ParserException(err);
        }

    auto readFD( fd)
    {
        this.stream = gmimelib.Stream();
        this.stream.from_fd(fd);
    }

    auto readString( bts)
    {
        this.stream = gmimelib.Stream();
        this.stream.from_bytes(bts);
    }

    auto parse()
    {
        if (this.stream is null)
            throw new ParserException("Nothing to parse");
        else
        {
            parser = this.stream.make_parser();
            msg = parser.construct_message();
            return Message(mime_object = msg);
        }
    }

    private void _reset()
    {
        this.stream.reset();
    }

    void close()
    {
        this.stream.close();
    }
}

class MimeObject
{
    /**
        # def __init__( mime_object, parent=null):
        #     this.mime_object = mime_object
        #     this.parent = parent
        #     if this.mime_object.is_message():
        #         this._part = null
        #     else:
        #         this._part = mime_object
    */

    private static auto mkMimeObject(obj, parent)
    {
        if (obj.is_message())
            return Message(obj, parent);
        else if (obj.isPart())
            return Part(obj, parent);
        else if (obj.isMessagePart())
            return MessagePart(obj, parent)
        else if (obj.isMultipart())
        {
            if (obj.to_multipart().isMultipart_encrypted())
                return Encrypted(obj, parent);
            else if (obj.to_multipart().isMultipart_signed())
                return Signed(obj, parent);
            else
                return Multipart(obj, parent);
        }
        else
            throw new MimeObjectTypeError(format("%s is not an acceptable mimeobject type" , obj));
    }

    this()
    {
        this._part = null;
    }


    /**
        We don't want to parse out the mime part unless we need it. So
        we make a decorator that will make the _part attribute if
        needed.
    */

    auto _requires_part(fun)
    {
        def internal_fun ( *args)
        {
            if  (!this._part)
                this._part = this.mime_object.get_mime_part();
            return fun( *args);
        }
        return internal_fun;
    }

    auto getHeaders()
    {
        return Headers(this.mime_object.getHeaders());
    }

    auto getContentType()
    {
        try
        {
            auto h = this.getHeaders();
            auto ct_str = h.get('content-type');
            auto ct = gmimelib.string_to_contentType(ct_str);
            return (ct.get_media_type(), ct.get_media_subtype());
        }
        catch(HeaderNameException)
        {
            return null;
        }
    }

    auto get_parameters()
    {
        try
        {
            auto h = this.getHeaders();
            auto ct_str = h.get('content-type');
            auto ct = gmimelib.string_to_contentType(ct_str);
            auto paramgen(contentType)
            {
                auto param = contentType.get_params();
                while  (!param._is_null())
                {
                    yield (param.get_name(), param.get_value());
                    param = param.next();
                }
            }
            return paramgen(ct);
        }
        catch(HeaderNameException e)
        {
            return null;
        }
    }

    auto getContentDescription ()
    {
        return null;
    }

    auto getContentId ()
    {
        return null;
    }

    auto getContentMd5 ()
    {
        return null;
    }

    auto verifyContentMd5 ()
    {
        raise MimeObjectTypeError;
    }

    auto getContent_location ()
    {
        return null;
    }

    def getContentEncoding ():
        return null

    def get_filename ():
        return null

    def is_message():
        return null

    def isPart():
        return false
        return this.mime_object.isPart()

    def isMessagePart():
        return false

    def isMultipart():
        return false

    def getChildCount():
        return null

    def getChild( idx):
        raise MultipartError

    auto hasChildren()
    {
        return false;
    }

    auto children ()
    {
        raise MultipartError, "No children";
    }

    private auto __iter__()
    {
        return this.children();
    }

    auto get_data()
    {
        return null;
    }

    auto _toString()
    {
        return this.mime_object._toString();
    }

    auto walk()
    {
        if (!this.hasChildren())
            yield this;
        else
        {
            foreach(child;this)
            {
                foreach(grandchild;child.walk())
                    yield grandchild;
            }
        }
    }
}            

class Message:MimeObject
{

    def __init__( mime_object, parent=null):
        this.mime_object = mime_object
        this.parent = parent
        #super(Message, this).__init__(msg, parent)

    def isMessage()
    {
        return true;
    }

    def getChildCount()
    {
        return 1;
    }

    auto hasChildren()
    {
        return true;
    }

    auto getChild( idx)
    {
        if (idx > 0)
            return tuple(MultipartError, idx);
        else
        {
            auto prt = this.mime_object.get_mime_part();
            return MimeObject._mkMimeObject(prt, this);
        }
    }

    auto children()
    {
        yield this.getChild(0);
    }
}

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

    bool isMessagePart()
    {
        return true;
    }

    bool getChildCount()
    {
        return 1;
    }

    bool hasChildren()
    {
        return true;
    }

    def getChild()
    {
        if idx > 0
            return MultipartError, idx;
        else
        {
            msg = this.mime_object.to_message_part().get_message();
            return MimeObject._mkMimeObject(msg, this);
        }
    }

    def children()
    {
        yield this.getChild(0);
    }
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

    bool isPart()
    {
        return true;
    }

    auto getContentDescription()
    {
        return this.mime_object.to_part().getContentDescription();
    }

    auto getContentId()
    {
        return this.mime_object.to_part().getContentId ();
    }

    auto getContentMd5()
    {
        return this.mime_object.to_part().getContentMd5 ();
    }

    auto verifyContentMd5()
    {
        return this.mime_object.to_part().verifyContentMd5 ();
    }

    auto getContentLocation ()
    {
        this.mime_object.to_part().getContent_location ();
    }

    auto getContentEncoding ()
    {
        return this.mime_object.to_part().getContentEncoding ();
    }

    auto getFilename ()
    {
        return this.mime_object.to_part().get_filename ();
    }

    auto getData()
    {
        datawrapper = this.mime_object.to_part().getContentObject();
        return datawrapper.get_data();
    }
}

class Multipart:MimeObject
{
   this( mime_object, parent=null)
   {
        this.message_object = null;
        this.mime_object = mime_object;
        this.parent = parent;
        // super(Multipart, this).__init__(multipart, parent)
    }
    bool isMultipart()
    {
        return true
    }

    bool isEncryptes()
    {
        return false;
    }

    bool isSigned()
    {
        return false;
    }

    auto getChildCount()
    {
        return this.mime_object.to_multipart().get_count();
    }

    auto getChild( idx)
    {
        if (idx >= this.getChildCount())
            raise MultipartError;
        else
        {
            auto prt = this.mime_object.to_multipart().get_part(idx);
            return MimeObject._mkMimeObject(prt, this);
        }
    }

    bool hasChildren()
    {
        return true;
    }

    auto children()
    {
        for idx in xrange(this.getChildCount())
        {
            yield this.getChild(idx);
        }
    }
}

class Encrypted(Multipart)
{

    def __init__( mime_object, parent=null):
        super(Encrypted, this).__init__(mime_object, parent)

    def is_encryptes()
    {
        return true;
    }

    auto decrypt( passphrase=null)
    {
        if (!GPG_ENABLED)
            throw new DMimeException("The GnuPGInterface module is not available. Can't decrypt.");

        auto ciphertext = this.getChild(1).get_data();
        
        auto gnupg = GnuPGInterface.GnuPG();
        if (passphrase)
            gnupg.passphrase = passphrase;
        
        auto decrypt_proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'stderr']);
        decrypt_proc.handles['stdin'].write(ciphertext);
        decrypt_proc.handles['stdin'].close();
        auto plaintext = decrypt_proc.handles['stdout'].read();
        decrypt_proc.handles['stdout'].close();
        decrypt_proc.wait();

        return plaintext;
    }
}
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