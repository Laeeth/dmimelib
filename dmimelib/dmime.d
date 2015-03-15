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
        priaddress_generator(add_lst):
            for i in xrange(len(add_lst)):
                yield add_lst[i]
        return address_generator()
    }

    private auto __bool__()
    {
        return len();
    }

    private auto  __str__()
    {
       return this._gm_address_list.to_string();
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

    def read_file( filename)
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

    auto read_fd( fd)
    {
        this.stream = gmimelib.Stream();
        this.stream.from_fd(fd);
    }

    auto read_string( bts)
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

    private static auto mk_mime_object(obj, parent)
    {
        if (obj.is_message())
            return Message(obj, parent);
        else if (obj.is_part())
            return Part(obj, parent);
        else if (obj.is_message_part())
            return MessagePart(obj, parent)
        else if (obj.is_multipart())
        {
            if (obj.to_multipart().is_multipart_encrypted())
                return Encrypted(obj, parent);
            else if (obj.to_multipart().is_multipart_signed())
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

    auto get_headers()
    {
        return Headers(this.mime_object.get_headers());
    }

    auto get_content_type()
    {
        try
        {
            auto h = this.get_headers();
            auto ct_str = h.get('content-type');
            auto ct = gmimelib.string_to_content_type(ct_str);
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
            auto h = this.get_headers();
            auto ct_str = h.get('content-type');
            auto ct = gmimelib.string_to_content_type(ct_str);
            auto paramgen(content_type)
            {
                auto param = content_type.get_params();
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

    auto get_content_description ()
    {
        return null;
    }

    auto get_content_id ()
    {
        return null;
    }

    auto get_content_md5 ()
    {
        return null;
    }

    auto verify_content_md5 ()
    {
        raise MimeObjectTypeError;
    }

    auto get_content_location ()
    {
        return null;
    }

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

    auto has_children()
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

    auto to_string()
    {
        return this.mime_object.to_string();
    }

    auto walk()
    {
        if (!this.has_children())
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
            return MimeObject._mk_mime_object(prt, this);
        }
    }

    auto children()
    {
        yield this.get_child(0);
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

    bool is_part()
    {
        return true;
    }

    auto get_content_description ()
    {
        return this.mime_object.to_part().get_content_description();
    }

    auto get_content_id ()
    {
        return this.mime_object.to_part().get_content_id ();
    }

    auto get_content_md5 ()
    {
        return this.mime_object.to_part().get_content_md5 ();
    }

    auto verify_content_md5
    {
        return this.mime_object.to_part().verify_content_md5 ();
    }

    auto get_content_location ()
    {
        this.mime_object.to_part().get_content_location ();
    }

    auto get_content_encoding ()
    {
        return this.mime_object.to_part().get_content_encoding ();
    }

    auto get_filename ()
    {
        return this.mime_object.to_part().get_filename ();
    }

    auto get_data()
    {
        datawrapper = this.mime_object.to_part().get_content_object();
        return datawrapper.get_data();
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
    bool is_multipart()
    {
        return true
    }

    bool is_encryptes()
    {
        return false;
    }

    bool is_signed()
    {
        return false;
    }

    auto get_child_count()
    {
        return this.mime_object.to_multipart().get_count();
    }

    auto get_child( idx)
    {
        if (idx >= this.get_child_count())
            raise MultipartError;
        else
        {
            auto prt = this.mime_object.to_multipart().get_part(idx);
            return MimeObject._mk_mime_object(prt, this);
        }
    }

    def has_children():
        return true

    def children():
        for idx in xrange(this.get_child_count()):
            yield this.get_child(idx)
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

        auto ciphertext = this.get_child(1).get_data();
        
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