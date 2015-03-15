
void init()
{
    g_mime_init(0);
}

void init(int flags)
{
    g_mime_init(flags);
}

/**
    UTILS
*/

auto decode_header_date(char *date)
{
    /**
        Note that while the tz_offset optionally goes into a pointer in
        gmime, I'm just returning a double here, and applications can
        decide what they want to do with the offset.
    */
    int tz_offset;
    auto timestamp = g_mime_utils_header_decode_date(date, &tz_offset);
    return tuple(timestamp, tz_offset);
}

ubyte* generate_message_id (ubyte *fqdn)
{
    return g_mime_utils_generate_message_id(fqdn);
}

def decode_message_id (char *message_id):
    return g_mime_utils_decode_message_id(message_id)

/**
    REFERENCES
*/
struct References
{
    GMimeReferences *_c_gmreferences;

    auto getMessageId()
    {
        return g_mime_references_get_message_id(this._c_gmreferences);
    }

    auto get_next()
    {
        GMimeReferences *next_gmr = g_mime_references_get_next(this._c_gmreferences);
        return mk_references(next_gmr);
    }
    
    void append(char *msg_id)
    {
        g_mime_references_append(&this._c_gmreferences, msg_id);
    }

    def isNull()
    {
        return this._c_gmreferences == null;
    }
}


// static initializer
References mk_references(GMimeReferences *gmr)
{
    auto refs = References();
    refs._c_gmreferences = gmr;
    return refs;
}

// text to References
auto decode_references(char *text)
{
    GMimeReferences *gmr = g_mime_references_decode(text);
    return mk_references(gmr);
}

/**
    STREAM
*/

class Stream
{
    GMimeStream *_c_gmstream

    this(GMimeStream* _c_gmstream)
    {
        this._c_gmstream = _c_gmstream;
    }

    this(char* filename)
    {
        cdef FILE* fp = fopen(filename, "rb");
        if (fp == null)
            throw new Exception(format("File %s not found",filename));
        GMimeStream *gms = g_mime_stream_file_new(fp);
        this._from_gmime_stream(gms);
    }

    this(int fd)
    {
        GMimeStream *gms = g_mime_stream_fs_new(fd);
        this._from_gmime_stream(gms);
    }

    void from_stdin()
    {
        GMimeStream *gms = g_mime_stream_file_new(stdin);
        this._from_gmime_stream(gms);
    }

    this(ubyte[] data)
    {
        GByteArray *garray = g_byte_array_new();
        g_byte_array_append(garray, data, len(data));
        cdef GMimeStream *gms = g_mime_stream_mem_new_with_byte_array(garray);
        this._from_gmime_stream(gms);
    }

    auto makeParser()
    {
        GMimeParser *gmp = g_mime_parser_new_with_stream(this._c_gmstream);
        return mk_parser(gmp);
    }

    auto make_data_wrapper(GMimeContentEncoding encoding)
    {
        GMimeDataWrapper *gmdw = g_mime_data_wrapper_new_with_stream(this._c_gmstream, encoding);
        return mk_data_wrapper(gmdw);
    }

    void reset()
    {
        g_mime_stream_reset(this._c_gmstream);
    }

    auto size()
    {
        return g_mime_stream_length(this._c_gmstream);
    }

    auto tell()
    {
        return g_mime_stream_tell(this._c_gmstream);
    }

    void flush()
    {
        g_mime_stream_flush(this._c_gmstream);
    }

    void close()
    {
        out = g_mime_stream_close(this._c_gmstream);
        if (out != 0)
            throw new Exception("Couldn't close the stream.");
    }
}
/**
    PARSER
*/

class Parser
{
    GMimeParser *_c_gmparser;

    auto constructPart()
    {
        return mk_mime_object(g_mime_parser_construct_part(this._c_gmparser));
    }

    auto constructMessage()
    {
        GMimeMessage *msg = g_mime_parser_construct_message(this._c_gmparser);
        return mk_message(msg);
    }
}

// Initializer from a GMimeStream
Parser mk_parser (GMimeParser *gmp)
{
    p = Parser();
    p._c_gmparser = gmp;
    return p;
}

/**
    DATA WRAPPER
*/

class DataWrapper
{
    cdef GMimeDataWrapper *_c_gmdatawrapper;

    auto get_data()
    {
        cdef GByteArray *garray = g_byte_array_new()
        cdef GMimeStream *outstream = \
             g_mime_stream_mem_new_with_byte_array(garray)
        g_mime_data_wrapper_write_to_stream (this._c_gmdatawrapper, outstream)
        # We have to call an explicit slice to get the length, because
        # strlen() will fail with bytearrays that have \x00 in them.
        return garray.data[:g_mime_stream_length(outstream)];;
    }
}


// Initializer from a GMimeDataWrapper
auto DataWrapper mk_data_wrapper (GMimeDataWrapper *gmdw)
{
    auto dw = DataWrapper();
    dw._c_gmdatawrapper = gmdw;
    return dw;
}

/**
    CIPHER CONTEXT
*/

class CipherContext
{
    GMimeCipherContext *_c_gmciphercontext;

    auto isGpgContext()
    {
        return GMIME_IS_GPG_CONTEXT(this._c_gmciphercontext);
    }

    def toGpgContext()
    {
        return mk_gpg_context (GMIME_GPG_CONTEXT(this._c_gmciphercontext));
    }
}

// Initializer from a GMimeCipherContext
CipherContext mk_cipher_context (GMimeCipherContext *gmctx)
{
    auto ctx = CipherContext();
    ctx._c_gmciphercontext = gmctx;
    return ctx;
}

/**
    GPG CIPHER CONTEXT
*/

class GPGContext(CipherContext)
{
    GMimeGpgContext *_c_gmgpgcontext;

    void setAlwaysTrust(bint always_trust)
    {
        g_mime_gpg_context_set_always_trust(this._c_gmgpgcontext, always_trust);
    }
}

// Initializer from a GMimeGpgContext
cdef GPGContext mkGpgContext (GMimeGpgContext *gmgpg)
{
    auto ctx = GPGContext();
    ctx._c_gmgpgcontext = gmgpg;
    ctx._c_gmciphercontext = GMIME_CIPHER_CONTEXT(gmgpg);
    return ctx;
}

/**
    GMIME SESSION
*/

class Session
{
    cdef GMimeSession *_c_gmsession;

    this()
    {
        this._c_gmsession = GMIME_SESSION (g_object_new( g_mime_session_get_type(), null) );
    }

    auto requestPassword(char* prompt, bint secret, char *item)
    {
        GError *err = null;
        char *passwd = g_mime_session_request_passwd(this._c_gmsession, prompt, secret, item, &err);
        if (err !is null)
            throw new Exception("Error requesting password: " ~ err.message);
        else
            return passwd;
    }

    void forgetPassword(char *item)
    {
        cdef GError *err = null;
        g_mime_session_forget_passwd(this._c_gmsession, item, &err);
        if (err !is null)
            throw new Exception("Error forgetting password: " ~ err.message);
    }

    auto isOnline()
    {
        return g_mime_session_is_online (this._c_gmsession);
    }

    auto newGpgContext(char *path)
    {
        GMimeCipherContext *ctx = g_mime_gpg_context_new(this._c_gmsession, path);
        return mk_cipher_context(ctx);
    }
}

/**
    GMIME SESSION SIMPLE (SESSION)
*/

class SessionSimple:Session
{
    cdef GMimeSessionSimple *_c_gmsessionsimple;

    this()
    {
        super(SessionSimple, this).__init__();
    }
}

/**
    MIME OBJECT
*/

class MimeObject
{
    /**
        Note: To try to deal correctly with the way that GMime
        implements its object hierarchy, every method that is inherited by
        MimeObject's subclasses does a cast first."""
    */

    GMimeObject *_c_gmobject;

    auto getHeaders()
    {
        GMimeHeaderList *gmhl = g_mime_object_get_header_list(this._c_gmobject);
        return mk_header_list(gmhl);
    }

    auto toString()
    {
        return g_mime_object_to_string (this._c_gmobject);
    }

    auto makeStream()
    {
        GMimeStream *gmstrm = g_mime_stream_mem_new ();
        g_mime_object_write_to_stream(this._c_gmobject, gmstrm);
        auto stream = Stream();
        stream._from_gmime_stream(gmstrm);
        stream.reset();
        return stream;
    }

    auto isPart()
    {
        return GMIME_IS_PART (this._c_gmobject);
    }

    auto toPart()
    {
        if not this.is_part()
            throw new Exception("Can't convert to part");

        GMimePart *gmp = GMIME_PART (this._c_gmobject);
        return mk_part(gmp);
    }
    
    auto isMultipart()
    {
        return GMIME_IS_MULTIPART (this._c_gmobject);
    }

    auto toMultipart()
    {
        if not this.isMultipart()
            throw new Exception("Can't convert to multipart");

        GMimeMultipart *gmmp = GMIME_MULTIPART (this._c_gmobject);
        return mk_multipart(gmmp);
    }

    auto isMessage()
    {
        return GMIME_IS_MESSAGE (this._c_gmobject);
    }

    auto toMessage()
    {
        if (!this.isMessage())
            throw new Exception("Can't convert to message");
        GMimeMessage *gmsg = GMIME_MESSAGE(this._c_gmobject);
        return mk_message(gmsg);
    }

    auto isMessagePart()
    {
        return GMIME_IS_MESSAGE_PART (this._c_gmobject);
    }

    auto toMessagePart()
    {
        if  (!this.isMessagePart())
            throw new Exception("Can't convert to message");
        GMimeMessagePart *gmsgprt = GMIME_MESSAGE_PART(this._c_gmobject);
        return mk_message_part(gmsgprt);
    }
}
// Static initalizer
MimeObject mk_mime_object(GMimeObject *obj)
{
    auto mo = MimeObject();
    mo._c_gmobject = obj;
    return mo;
}

/**
    PART (MIME OBJECT)
*/

class Part:MimeObject
{

    GMimePart *_c_gmpart

    this()
    {
        MimeObject.__init__()
    }

    auto getContentObject()
    {
        GMimeObject *gmobj = this._c_gmobject;
        GMimeDataWrapper *gmdw = g_mime_part_get_content_object (GMIME_PART(gmobj));
        return mk_data_wrapper(gmdw);
    }
        
    auto getContentDescription ()
    {
        return g_mime_part_get_content_description (this._c_gmpart);
    }

    auto getContentId()
    {
        return g_mime_part_get_content_id (this._c_gmpart);
    }

    auto getContentMd5()
    {
        return g_mime_part_get_content_md5 (this._c_gmpart);
    }

    auto verifyContentMd5()
    {
        return g_mime_part_verify_content_md5 (this._c_gmpart);
    }

    auto getContentLocation ()
    {
        return g_mime_part_get_content_location (this._c_gmpart);
    }

    auto getContentEncoding()
    {
        return g_mime_part_get_content_encoding (this._c_gmpart);
    }

    auto getFilename()
    {
        return g_mime_part_get_filename (this._c_gmpart);
    }
}

// Static initalizer
Part mk_part(GMimePart *gmp)
{
    auto p = Part()
    p._c_gmpart = gmp;
    p._c_gmobject = GMIME_OBJECT(gmp);
    return p;
}

/**
    MULTIPART (MIME OBJECT)
*/

class Multipart:MimeObject
{
    GMimeMultipart *_c_gmmultipart;

    this()
    {
        MimeObject.__init__();
    }

    def get_count():
        return g_mime_multipart_get_count (this._c_gmmultipart)

    def get_part(int partidx):
        cdef GMimeObject *obj = g_mime_multipart_get_part (this._c_gmmultipart,
                                                           partidx)
        return mk_mime_object(obj)

    def get_subpart_from_content_id (char *content_id):
        cdef GMimeObject *obj = \
             g_mime_multipart_get_subpart_from_content_id (this._c_gmmultipart,
                                                           content_id)

        return mk_mime_object(obj)

    def is_multipart_encrypted():
        return GMIME_IS_MULTIPART_ENCRYPTED (this._c_gmobject)

    auto toMultipartEncrypted()
    {
        if (!this.isMultipart())
            throw new Exception("Can't convert to multipart encrypted");

        cdef GMimeMultipartEncrypted *gmme = GMIME_MULTIPART_ENCRYPTED (this._c_gmobject)
        return mk_multipart_encrypted(gmme);
    }

    auto isMultipartSigned()
    {
        return GMIME_IS_MULTIPART_SIGNED (this._c_gmobject);
    }

    auto toMultipartSigned()
    {
        if  (!this.is_multipart())
            throw new Exception("Can't convert to multipart encrypted");

        GMimeMultipartSigned *gmms = GMIME_MULTIPART_SIGNED (this._c_gmobject);
        return mk_multipart_signed(gmms);
    }
}

# Static initalizer
cdef Multipart mk_multipart(GMimeMultipart *gmmp):
    mp = Multipart()
    mp._c_gmmultipart = gmmp
    mp._c_gmobject = GMIME_OBJECT(gmmp)
    return mp

##############################################################################
## MULTIPART ENCRYPTED (MULTIPART)
##############################################################################

class MultipartEncrypted(Multipart):

    cdef GMimeMultipartEncrypted *_c_gmmultipartencrypted

    def __cinit__():
        Multipart.__init__()

    def decrypt(CipherContext ctx):
        cdef GError *err = null
        cdef GMimeObject *obj = \
            g_mime_multipart_encrypted_decrypt(this._c_gmmultipartencrypted,
                                               ctx._c_gmciphercontext,
                                               &err)
        if err != null:
            raise Exception, "decryption failed: " + err.message
        else:
            return mk_mime_object(obj)

# Static initializer
cdef MultipartEncrypted mk_multipart_encrypted(GMimeMultipartEncrypted *gmpe):
    mpe = MultipartEncrypted()
    mpe._c_gmmultipartencrypted = gmpe
    mpe._c_gmobject = GMIME_OBJECT(gmpe)
    mpe._c_gmmultipart = GMIME_MULTIPART(mpe._c_gmobject)
    return mpe

##############################################################################
## MULTIPART SIGNED (MULTIPART)
##############################################################################

class MultipartSigned(Multipart):

    cdef GMimeMultipartSigned *_c_gmmultipartsigned

    def __cinit__():
        Multipart.__init__()

    # def verify(CipherContext ctx):
    #     cdef GError *err = null
    #     cdef GMimeSignatureValidity *sigval = \
    #         g_mime_multipart_signed_verify(this._c_gmmultipartsigned,
    #                                        ctx._c_gmciphercontext,
    #                                        &err)
    #     if err != null:
    #         raise Exception, "Verification failed: " + err.message
    #     else:
    #         return mk_signature_validity(sigval)

# Static initializer
cdef MultipartEncrypted mk_multipart_signed(GMimeMultipartSigned *gmps):
    mps = MultipartSigned()
    mps._c_gmmultipartsigned = gmps
    mps._c_gmobject = GMIME_OBJECT(gmps)
    mps._c_gmmultipart = GMIME_MULTIPART(mps._c_gmobject)
    return mps

##############################################################################
## MESSAGE (MIME OBJECT)
##############################################################################

class Message (MimeObject):

    cdef GMimeMessage *_c_gmmessage

    def __cinit__():
        MimeObject.__init__()

    def get_sender():
        return g_mime_message_get_sender(this._c_gmmessage)

    def get_reply_to():
        return g_mime_message_get_reply_to(this._c_gmmessage)

    def get_subject():
        return g_mime_message_get_subject(this._c_gmmessage) 

    def get_date_as_string():
        return g_mime_message_get_date_as_string(this._c_gmmessage) 

    def get_message_id():
        return g_mime_message_get_message_id(this._c_gmmessage)

    def get_mime_part():
        cdef GMimeObject *obj = g_mime_message_get_mime_part(this._c_gmmessage)
        return mk_mime_object(obj)

# Static initalizer
cdef Message mk_message(GMimeMessage *gmmsg):
    msg = Message()
    msg._c_gmmessage = gmmsg
    msg._c_gmobject = GMIME_OBJECT(gmmsg)
    return msg

##############################################################################
## MESSAGE PART (MIME OBJECT)
##############################################################################

class MessagePart(MimeObject):

    cdef GMimeMessagePart *_c_gmmessagepart

    def __cinit__():
        MimeObject.__init__()

    def get_message():
        cdef GMimeMessage *gmmsg = \
             g_mime_message_part_get_message(this._c_gmmessagepart)
        return mk_message(gmmsg)

# Static initalizer
cdef MessagePart mk_message_part(GMimeMessagePart *gmmp):
    msgpart = MessagePart()
    msgpart._c_gmmessagepart = gmmp
    msgpart._c_gmobject = GMIME_OBJECT(gmmp)
    return msgpart

##############################################################################
## HEADERS
##############################################################################

class Headers(object):
    cdef GMimeHeaderList *_c_gmheaderlist
    cdef GMimeHeaderIter *_header_iter
    cdef bint _iter_done

    def __cinit__():
        this._iter_done = false

    def iter_get_name():
        return g_mime_header_iter_get_name (this._header_iter)

    def iter_get_value():
        return g_mime_header_iter_get_value (this._header_iter)

    def iter_first ():
        return g_mime_header_iter_first (this._header_iter)

    def iter_last ():
        return g_mime_header_iter_last (this._header_iter)

    def iter_next ():
        return g_mime_header_iter_next (this._header_iter)

    def iter_prev ():
        return g_mime_header_iter_prev (this._header_iter)

    def iter_is_valid ():
        return g_mime_header_iter_is_valid (this._header_iter)

    def get(char *name):
        value = g_mime_header_list_get(this._c_gmheaderlist, name)
        if value == null:
            raise KeyError, name
        else:
            return value

# Initializer from GMimeHeaderList
cdef Headers mk_header_list(GMimeHeaderList *gmhdrs):
    h = Headers()
    h._c_gmheaderlist = gmhdrs
    h._header_iter = g_mime_header_iter_new()
    g_mime_header_list_get_iter(h._c_gmheaderlist, h._header_iter)
    return h

##############################################################################
## CONTENT-TYPE 
##############################################################################

class ContentType(object):
    cdef GMimeContentType *_c_gmcontenttype
    
    # cdef _from_gmime_content_type(GMimeContentType *gmct):
    #     this._c_gmcontenttype = gmct

    # def new_from_string(this,s):
    #     this._from_gmime_content_type(g_mime_content_type_new_from_string (s))

    def to_string():
        return g_mime_content_type_to_string (this._c_gmcontenttype)

    def get_media_type ():
        return g_mime_content_type_get_media_type (this._c_gmcontenttype)

    def get_media_subtype ():
        return g_mime_content_type_get_media_subtype (this._c_gmcontenttype)

    def get_params ():
        cdef GMimeParam* gmp = g_mime_content_type_get_params (this._c_gmcontenttype)
        return mk_parameters(gmp)

    def get_parameter (char *attribute):
        return g_mime_content_type_get_parameter (this._c_gmcontenttype, attribute)


# Static construction function
def string_to_content_type(char *string):
    """A static function that takes a string and returns a
    ContentType() class."""
    cdef ContentType ct = ContentType()
    ct._c_gmcontenttype = g_mime_content_type_new_from_string (string)
    return ct


/**
    PARAMETERS
*/

class Param()
{
    GMimeParam *_c_gmparameters;
    
    bool _is_null()
    {
        return (this._c_gmparameters == null);
    }
    
    auto next()
    {
        return mk_parameters(g_mime_param_next (this._c_gmparameters));
    }
                                                               
    auto get_name()
    {                                        
        if this._is_null()                                    
            return null;                                        
        else                                     
            return g_mime_param_get_name(this._c_gmparameters);
    }
                                                               
    def get_value():                                       
        if this._is_null():                                    
            return null
        else:
            return g_mime_param_get_value(this._c_gmparameters)

    cdef _from_gmime_parameters(GMimeParam *gmp):
        this._c_gmparameters = gmp
}

// Static initalizer
Param mk_parameters(GMimeParam *gmp)
{
    param = Param();
    param._c_gmparameters = gmp;
    return param;
}
/**
    CONTENT-DISPOSITION
*/

class ContentDisposition
{
    GMimeContentDisposition *_c_gmcontentdisposition;
    
    void _from_gmime_content_disposition(GMimeContentDisposition *gmd)
    {
        this._c_gmcontentdisposition = gmd;
    }

    void new_from_string(s)
    {
        this._from_gmime_content_disposition(g_mime_content_disposition_new_from_string (s))
    }

    auto get_disposition()
    {
        return g_mime_content_disposition_get_disposition (this._c_gmcontentdisposition);
    }

    auto get_params()
    {
        cdef GMimeParam *gmp = g_mime_content_disposition_get_params (this._c_gmcontentdisposition);
        param = Param();
        param._from_gmime_parameters(gmp);
        return param;
    }

    auto get_parameter(char *attribute)
    {
        return g_mime_content_disposition_get_parameter (this._c_gmcontentdisposition, attribute);
    }

    string toString(bint fold = true)
    {
        return g_mime_content_disposition_to_string (this._c_gmcontentdisposition, fold);
    }
}

// Static construction function
def string_to_content_disposition(char *string):
    """A static function that takes a string and returns a
    ContentDisposition() class."""
    cdef ContentDisposition cd = ContentDisposition()
    cd.new_from_string(string)
    return cd

/**
    INTERNET ADDRESS
*/

class InternetAddress(object):
    cdef CInternetAddress *_c_internet_address
    
    def get_name():
        out = internet_address_get_name(this._c_internet_address)
        if out is null:
            return null
        else:
            return out

    def set_name(char *name):
        internet_address_set_name(this._c_internet_address, name)

    def to_string(bint encode=true):
        return internet_address_to_string(this._c_internet_address, encode)

    def is_internet_address_mailbox():
        return INTERNET_ADDRESS_IS_MAILBOX(this._c_internet_address)

    def to_internet_address_mailbox():
        if not this.is_internet_address_mailbox():
            raise Exception, "Can't convert to message"
        cdef CInternetAddressMailbox *iam = INTERNET_ADDRESS_MAILBOX(this._c_internet_address)
        return mk_internet_address_mailbox(iam)

    def is_internet_address_group():
        return INTERNET_ADDRESS_IS_GROUP(this._c_internet_address)

    def to_internet_address_group():
        if not this.is_internet_address_group():
            raise Exception, "Can't convert to message"
        cdef CInternetAddressGroup *iag = INTERNET_ADDRESS_GROUP(this._c_internet_address)
        return mk_internet_address_group(iag)

    def to_internet_address():
        return <InternetAddress>self

cdef InternetAddress mk_internet_address(CInternetAddress *cia):
     ia = InternetAddress()
     ia._c_internet_address = cia
     return ia

/**
    INTERNET ADDRESS LIST
*/

class InternetAddressListError(Exception):
    pass

class InternetAddressList
{
   cdef CInternetAddressList *_c_internet_address_list

    this()
    {
        this._c_internet_address_list = internet_address_list_new();
    }
    
    size_t length()
    {
        return internet_address_list_length(this._c_internet_address_list);
    }

    auto contains(InternetAddress ia)
    {
        return internet_address_list_contains(this._c_internet_address_list, ia._c_internet_address);
    }

    auto index_of(InternetAddress ia)
    {
        return internet_address_list_index_of(this._c_internet_address_list, ia._c_internet_address);
    }

    auto get_address(int idx)
    {
        CInternetAddress *cia = internet_address_list_get_address (this._c_internet_address_list, idx);
        return mk_internet_address(cia);
    }

    string toString(bool encode=true):
        out_str = internet_address_list_to_string(this._c_internet_address_list, encode)
        if out_str == null:
            return ""
        else:
            return out_str

    def append(InternetAddressList other):
        internet_address_list_append(this._c_internet_address_list,
                                     other._c_internet_address_list)

    def add(InternetAddress addr):
        idx = internet_address_list_add (this._c_internet_address_list,
                                         addr._c_internet_address)
        return idx

    def insert(InternetAddress addr, int idx):
        internet_address_list_insert (this._c_internet_address_list,
                                      idx,
                                      addr._c_internet_address)

    def remove(InternetAddress addr):
        out_bool = internet_address_list_remove (this._c_internet_address_list,
                                                 addr._c_internet_address)
        if not out_bool:
            raise InternetAddressListError, "Couldn't remove item %s" % addr

    def remove_at(int idx):
        out_bool = internet_address_list_remove_at (this._c_internet_address_list,
                                                    idx)
        if not out_bool:
            raise InternetAddressListError, "Couldn't remove item at index %d" % idx


cdef InternetAddressList mk_internet_address_list(CInternetAddressList *cial):
    cdef InternetAddressList ial = InternetAddressList()
    ial._c_internet_address_list = cial
    return ial


# Static construction function
def parse_internet_address_list(char *s):
    """A static function that takes a string and returns an
    InternetAddressList() object."""
    cdef CInternetAddressList *cial = internet_address_list_parse_string (s)
    return mk_internet_address_list(cial)

/**
    INTERNET ADDRESS MAILBOX (STANDARD ADDRESS)
*/

class InternetAddressMailbox:InternetAddress
{
    CInternetAddressMailbox *_c_internet_address_mailbox;

    this(char *name, char *addr)
    {
        this._c_internet_address = internet_address_mailbox_new(name, addr);
        this._c_internet_address_mailbox = INTERNET_ADDRESS_MAILBOX (this._c_internet_address);
    }

    auto getAddr()
    {
        return internet_address_mailbox_get_addr(this._c_internet_address_mailbox);
    }

    void setAddr(char *addr)
    {
        internet_address_mailbox_set_addr(this._c_internet_address_mailbox, addr);
    }
}        

cdef InternetAddressMailbox mk_internet_address_mailbox(CInternetAddressMailbox *iam):
    mailbox = InternetAddressMailbox("", "")
    mailbox._c_internet_address_mailbox = iam
    mailbox._c_internet_address = INTERNET_ADDRESS(iam)
    return mailbox

/**
    INTERNET ADDRESS GROUP 
*/

class InternetAddressGroup:InternetAddress
{
    CInternetAddressGroup *_c_internet_address_group;

    this(char *name)
    {
        this._c_internet_address = internet_address_group_new(name);
        this._c_internet_address_group = INTERNET_ADDRESS_GROUP (this._c_internet_address);
    }

    auto getMembers()
    {
        CInternetAddressList *cial;
        cial = internet_address_group_getMembers(this._c_internet_address_group);
        return mk_internet_address_list(cial);
    }

    auto setMembers(InternetAddressList members)
    {
        internet_address_group_setMembers (this._c_internet_address_group,
                                            members._c_internet_address_list);
    }

    auto addMember(InternetAddress member)
    {
        return internet_address_group_add_member (this._c_internet_address_group,
                                                  member._c_internet_address);
    }
}
InternetAddressGroup mk_internet_address_group(CInternetAddressGroup *iag)
{
    auto group = InternetAddressGroup("");
    group._c_internet_address_group = iag;
    group._c_internet_address = INTERNET_ADDRESS(iag);
    return group;
}



        

        

