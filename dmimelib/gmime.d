module dmimelib.gmime;
import std.stdio;
import std.conv;
import std.exception;
import std.typecons;
import dmimelib.cbindings;

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

auto decodeHeaderDate(char *date)
{
    /**
        Note that while the tz_offset optionally goes into a pointer in
        gmime, I'm just returning a double here, and applications can
        decide what they want to do with the offset.
    */
    int tz_offset;
    auto timestamp = g_mime_utils_header_decode_date(cast(ubyte*)date, &tz_offset);
    return tuple(timestamp, tz_offset);
}

ubyte* generateMessageId (ubyte *fqdn)
{
    return g_mime_utils_generate_message_id(fqdn);
}

auto decodeMessageId (char *message_id)
{
    return g_mime_utils_decode_message_id(cast(ubyte*)message_id);
}

/**
    REFERENCES
*/
struct References
{
    GMimeReferences *_c_gmreferences;

    this(GMimeReferences *gmr)
    {
        this._c_gmreferences = gmr;
    }
    auto getMessageId()
    {
        return g_mime_references_get_message_id(this._c_gmreferences);
    }

    auto get_next()
    {
        GMimeReferences *next_gmr = g_mime_references_get_next(this._c_gmreferences);
        return mkReferences(next_gmr);
    }
    
    void append(char *msg_id)
    {
        g_mime_references_append(&this._c_gmreferences, cast(ubyte*)msg_id);
    }

    auto isNull()
    {
        return this._c_gmreferences is null;
    }
}


// static initializer
auto mkReferences(GMimeReferences *gmr)
{
    return new References(gmr);
}

// text to References
auto decodeReferences(char *text)
{
    GMimeReferences *gmr = g_mime_references_decode(cast(ubyte*)text);
    return mkReferences(gmr);
}

/**
    STREAM
*/

class Stream
{
    GMimeStream *_c_gmstream;

    this(GMimeStream* _c_gmstream)
    {
        this._c_gmstream = _c_gmstream;
    }

    this(char* filename)
    {
        FILE* fp = fopen(filename, "rb");
        if (fp is null)
            throw new Exception(format("File %s not found",filename));
        GMimeStream *gms = g_mime_stream_file_new(fp);
        this(gms);
    }

    this(int fd)
    {
        GMimeStream *gms = g_mime_stream_fs_new(fd);
        this(gms);
    }

    this()
    {
        GMimeStream *gms = g_mime_stream_file_new(stdin);
        this(gms);
    }

    this(ubyte[] data)
    {
        GByteArray *garray = g_byte_array_new();
        g_byte_array_append(garray, data, len(data));
        GMimeStream *gms = g_mime_stream_mem_new_with_byte_array(garray);
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
        auto ret = g_mime_stream_close(this._c_gmstream);
        if (ret != 0)
            throw new Exception("Couldn't close the stream.");
    }
}
/**
    PARSER
*/

class Parser
{
    GMimeParser *_c_gmparser;

    // Initializer from a GMimeStream
    this(GMimeParser *gmp)
    {
        this._c_gmparser = gmp;
    }

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
Parser mkParser (GMimeParser *gmp)
{
    return Parser(gmp);
}

/**
    DATA WRAPPER
*/

class DataWrapper
{
    GMimeDataWrapper *_c_gmdatawrapper;

    this(GMimeDataWrapper *gmdw)
    {
        this._c_gmdatawrapper = gmdw;
    }

    auto getData()
    {
        GByteArray *garray = g_byte_array_new();
        GMimeStream *outstream = g_mime_stream_mem_new_with_byte_array(garray);
        g_mime_data_wrapper_write_to_stream (this._c_gmdatawrapper, outstream);
        // We have to call an explicit slice to get the length, because strlen() will fail with bytearrays that have \x00 in them.
        return garray.data[0..g_mime_stream_length(outstream)];
    }
}


// Initializer from a GMimeDataWrapper
DataWrapper mkDataWrapper (GMimeDataWrapper *gmdw)
{
    return new DataWrapper(gmdw);
}

/**
    CIPHER CONTEXT
*/

class CipherContext
{
    GMimeCipherContext *_c_gmciphercontext;

    this(GMimeCipherContext *gmctx)
    {
        this._c_gmciphercontext = gmctx;
    }

    auto isGpgContext()
    {
        return GMIME_IS_GPG_CONTEXT(this._c_gmciphercontext);
    }

    auto toGpgContext()
    {
        return mk_gpg_context (GMIME_GPG_CONTEXT(this._c_gmciphercontext));
    }
}

// Initializer from a GMimeCipherContext
CipherContext mkCipherContext (GMimeCipherContext *gmctx)
{
    return new CipherContext(gmctx);
}

/**
    GPG CIPHER CONTEXT
*/

class GPGContext(CipherContext)
{
    GMimeGpgContext *_c_gmgpgcontext;


    this(GMimeGpgContext *gmgpg)
    {
        this._c_gmgpgcontext = gmgpg;
        this._c_gmciphercontext = GMIME_CIPHER_CONTEXT(gmgpg);
    }

    void setAlwaysTrust(bint always_trust)
    {
        g_mime_gpg_context_set_always_trust(this._c_gmgpgcontext, always_trust);
    }
}

// Initializer from a GMimeGpgContext
auto mkGpgContext (GMimeGpgContext *gmgpg)
{
    return new GPGContext(gmgpg);
}

/**
    GMIME SESSION
*/

class Session
{
    GMimeSession *_c_gmsession;

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
        GError *err = null;
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
    GMimeSessionSimple *_c_gmsessionsimple;

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

    this (GMimeObject *obj)
    {
        this._c_gmobject = obj;
    }

    auto getHeaders()
    {
        GMimeHeaderList *gmhl = g_mime_object_get_header_list(this._c_gmobject);
        return mk_header_list(gmhl);
    }

    auto _toString()
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
        if (!this.isPart())
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
        if (!this.isMultipart())
            throw new Exception("Can't convert to multipart");

        GMimeMultipart *gmmp = GMIME_MULTIPART (this._c_gmobject);
        return mkMultipart(gmmp);
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
        return mkMessage(gmsg);
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
        return mkMessagePart(gmsgprt);
    }
}
// Static initalizer
MimeObject mkMimeObject(GMimeObject *obj)
{
    return new MimeObject(obj);
}

/**
    PART (MIME OBJECT)
*/

class Part:MimeObject
{

    GMimePart *_c_gmpart;

    this()
    {
        //MimeObject.__init__()
    }
    
    this(GMimePart *gmp)
    {
        this._c_gmpart = gmp;
        this._c_gmobject = GMIME_OBJECT(gmp);
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
Part mkPart(GMimePart *gmp)
{
    return new Part(gmp);
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

    this(GMimeMultipart *gmmp)
    {
        MimeObject.__init__();
        this._c_gmmultipart = gmmp;
        this._c_gmobject = GMIME_OBJECT(gmmp);
    }

    auto getCount()
    {
        return g_mime_multipart_get_count (this._c_gmmultipart);
    }

    auto getPart(int partidx)
    {
        GMimeObject *obj = g_mime_multipart_get_part (this._c_gmmultipart, partidx);
        return mk_mime_object(obj);
    }

    void getSubpartFromContentId(char *content_id)
    {
        GMimeObject *obj = g_mime_multipart_get_subpart_from_content_id (this._c_gmmultipart, content_id);
    }

    auto isMultipartEncrypted()
    {
        return GMIME_IS_MULTIPART_ENCRYPTED (this._c_gmobject);
    }

    auto toMultipartEncrypted()
    {
        if (!this.isMultipart())
            throw new Exception("Can't convert to multipart encrypted");

        GMimeMultipartEncrypted *gmme = GMIME_MULTIPART_ENCRYPTED (this._c_gmobject);
        return mkMultipartEncrypted(gmme);
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

// Static initalizer
Multipart mkMultipart(GMimeMultipart *gmmp)
{
    return new Multipart(gmmp);
}

/**
    MULTIPART ENCRYPTED (MULTIPART)
*/

class MultipartEncrypted:Multipart
{
    GMimeMultipartEncrypted *_c_gmmultipartencrypted;

    this()
    {
        Multipart.__init__();
    }

    this(GMimeMultipartEncrypted *gmpe)
    {
        Multipart.__init__();
        this._c_gmmultipartencrypted = gmpe;
        this._c_gmobject = GMIME_OBJECT(gmpe);
        this._c_gmmultipart = GMIME_MULTIPART(mpe._c_gmobject);
    }

    auto decrypt(CipherContext ctx)
    {
        GError *err = null;
        GMimeObject *obj = g_mime_multipart_encrypted_decrypt(this._c_gmmultipartencrypted, ctx._c_gmciphercontext, &err);
        if (err !is null)
            throw new Exception, "decryption failed: " ~ err.message;
        else
            return mk_mime_object(obj);
    }
}

// Static initializer
MultipartEncrypted mkMultipartEncrypted(GMimeMultipartEncrypted *gmpe)
{
    return new MultipartEncrypted(gmpe);
}

/**
    MULTIPART SIGNED (MULTIPART)
*/

class MultipartSigned:Multipart
{
    GMimeMultipartSigned *_c_gmmultipartsigned;

    this()
    {
        Multipart.__init__();
    }


    /**
        def verify(CipherContext ctx):
            cdef GError *err = null
            cdef GMimeSignatureValidity *sigval = \
                g_mime_multipart_signed_verify(this._c_gmmultipartsigned,
                                               ctx._c_gmciphercontext,
                                               &err)
            if err != null:
                throw new Exception("Verification failed: " ~ err.message
            else:
                return mk_signature_validity(sigval)
    */

}

// Static initializer
MultipartEncrypted mkMultipartSigned(GMimeMultipartSigned *gmps)
{
    mps = MultipartSigned();
    mps._c_gmmultipartsigned = gmps;
    mps._c_gmobject = GMIME_OBJECT(gmps);
    mps._c_gmmultipart = GMIME_MULTIPART(mps._c_gmobject);
    return mps;
}

/**
    MESSAGE (MIME OBJECT)
*/

class Message:MimeObject
{

    GMimeMessage *_c_gmmessage;

    this()
    {
        MimeObject.__init__();
    }

    this(GMimeMessage *gmmsg)
    {
        MimeObject.__init__();
        this._c_gmmessage = gmmsg;
        this._c_gmobject = GMIME_OBJECT(gmmsg);
    }

    auto getSender()
    {
        return g_mime_message_get_sender(this._c_gmmessage);
    }

    auto getReplyTo()
    {
        return g_mime_message_get_reply_to(this._c_gmmessage);
    }

    auto getSubject()
    {
        return g_mime_message_get_subject(this._c_gmmessage);
    }

    auto getDateAsString()
    {
        return g_mime_message_get_date_as_string(this._c_gmmessage);
    }

    auto getMessageId()
    {
        return g_mime_message_get_message_id(this._c_gmmessage);
    }

    auto getMimePart()
    {
        GMimeObject *obj = g_mime_message_get_mime_part(this._c_gmmessage);
        return mk_mime_object(obj);
    }
}
// Static initalizer
Message mk_message(GMimeMessage *gmmsg)
{
    return new Message(gmmsg);
}

/**
    MESSAGE PART (MIME OBJECT)
*/

class MessagePart:MimeObject
{
    GMimeMessagePart *_c_gmmessagepart;

    this()
    {
        MimeObject.__init__();
    }

    this(GMimeMessagePart *gmmp)
    {
        this._c_gmmessagepart = gmmp;
        this._c_gmobject = GMIME_OBJECT(gmmp);
    }

    auto getMessage()
    {
        GMimeMessage *gmmsg = g_mime_message_part_get_message(this._c_gmmessagepart);
        return mk_message(gmmsg);
    }
}
// Static initalizer
MessagePart mkMessagePart(GMimeMessagePart *gmmp)
{
    return new MessagePart(gmmp);
}

/**
    HEADERS
*/

class Headers
{
    GMimeHeaderList *_c_gmheaderlist;
    GMimeHeaderIter *_header_iter;
    private bint iterDone;

    this()
    {
        this.iterDone = false;
    }

    this(GMimeHeaderList *gmhdrs)
    {
        this.iterDone = false;
        this._c_gmheaderlist = gmhdrs;
        this._header_iter = g_mime_header_iter_new();
        g_mime_header_list_get_iter(h._c_gmheaderlist, this._header_iter);
    }

    auto iterGetName()
    {
        return g_mime_header_iter_get_name (this._header_iter);
    }

    auto iterGetBalue()
    {
        return g_mime_header_iter_get_value (this._header_iter);
    }

    auto iterFirst ()
    {
        return g_mime_header_iter_first (this._header_iter);
    }

    auto iterLast ()
    {
        return g_mime_header_iter_last (this._header_iter);
    }

    auto iterNext ()
    {
        return g_mime_header_iter_next (this._header_iter);
    }

    auto iterPrev ()
    {
        return g_mime_header_iter_prev (this._header_iter);
    }

    auto iterIsValid ()
    {
        return g_mime_header_iter_is_valid (this._header_iter);
    }

    auto get(char *name)
    {
        auto value = g_mime_header_list_get(this._c_gmheaderlist, name);
        if (value is null)
            throw new Exception("KeyError: "~name);
        else
            return value;
    }
}

// Initializer from GMimeHeaderList
Headers mkHeaderList(GMimeHeaderList *gmhdrs)
{
    return new Headers(gmhdrs);
}

/**
    CONTENT-TYPE 
*/

class ContentType
{
    GMimeContentType *_c_gmcontenttype;
    
    /**
        cdef _from_gmime_content_type(GMimeContentType *gmct):
            this._c_gmcontenttype = gmct

        def new_from_string(this,s):
            this._from_gmime_content_type(g_mime_content_type_new_from_string (s))
    */

    string _toString()
    {
        return g_mime_content_type_to_string (this._c_gmcontenttype);
    }

    auto getMediaType ()
    {
        return g_mime_content_type_get_media_type (this._c_gmcontenttype);
    }

    auto getMediaSubtype ()
    {
        return g_mime_content_type_get_media_subtype (this._c_gmcontenttype);
    }

    auto getParams ()
    {
        GMimeParam* gmp = g_mime_content_type_get_params (this._c_gmcontenttype);
        return mk_parameters(gmp);
    }

    auto getParameter (char *attribute)
    {
        return g_mime_content_type_get_parameter (this._c_gmcontenttype, attribute);
    }
}


// Static construction function
auto stringToContentType(char *string)
{
    // A static function that takes a string and returns a ContentType() class.
    ContentType ct = ContentType();
    ct._c_gmcontenttype = g_mime_content_type_new_from_string (string);
    return ct;
}


/**
    PARAMETERS
*/

class Param
{
    GMimeParam *_c_gmparameters;
    
    private bool isNull()
    {
        return (this._c_gmparameters is null);
    }
    
    this(GMimeParam *gmp)
    {
        this._c_gmparameters = gmp;
    }

    auto next()
    {
        return mkParameters(g_mime_param_next (this._c_gmparameters));
    }
                                                               
    auto getName()
    {                                        
        if (this.isNull())
            return null;                                        
        else                                     
            return g_mime_param_get_name(this._c_gmparameters);
    }
                                                               
    auto getValue()
    {
        if (this.is_null())
            return null;
        else
            return g_mime_param_get_value(this._c_gmparameters);
    }

    void _from_gmime_parameters(GMimeParam *gmp)
    {
        this._c_gmparameters = gmp;
    }
}

// Static initalizer
Param mkParameters(GMimeParam *gmp)
{
    return new Param(gmp);
}
/**
    CONTENT-DISPOSITION
*/

class ContentDisposition
{
    GMimeContentDisposition *_c_gmcontentdisposition;
    
    this(GMimeContentDisposition *gmd)
    {
        this._c_gmcontentdisposition = gmd;
    }

    this(string s)
    {
        this._from_gmime_content_disposition(g_mime_content_disposition_new_from_string (s));
    }

    auto getDisposition()
    {
        return g_mime_content_disposition_get_disposition (this._c_gmcontentdisposition);
    }

    auto getParams()
    {
        GMimeParam *gmp = g_mime_content_disposition_get_params (this._c_gmcontentdisposition);
        param = Param();
        param._from_gmime_parameters(gmp);
        return param;
    }

    auto getParameter(char *attribute)
    {
        return g_mime_content_disposition_get_parameter (this._c_gmcontentdisposition, attribute);
    }

    string toString(bint fold = true)
    {
        return g_mime_content_disposition_to_string (this._c_gmcontentdisposition, fold);
    }
}

// Static construction function
ContentDisposition stringToContentDisposition(char *s)
{
    //A static function that takes a string and returns a ContentDisposition() class.
    return new ContentDisposition(s);
}

/**
    INTERNET ADDRESS
*/

class InternetAddress
{
    CInternetAddress *_c_internet_address;
    
    this(CInternetAddress *cia)
    {
         this._c_internet_address = cia;
    }

    auto getName()
    {
        return internet_address_get_name(this._c_internet_address);
    }
     
    void setName(char *name)
    {
        internet_address_set_name(this._c_internet_address, name);
    }

    string toString(bint encode=true)
    {
        return internet_address_to_string(this._c_internet_address, encode);
    }

    auto isInternetAddressMailbox()
    {
        return INTERNET_ADDRESS_IS_MAILBOX(this._c_internet_address);
    }

    auto toInternetAddressMailbox()
    {
        if (!this.is_internet_address_mailbox())
            throw new Exception("Can't convert to message");
        CInternetAddressMailbox *iam = INTERNET_ADDRESS_MAILBOX(this._c_internet_address);
        return mk_internet_address_mailbox(iam);
    }

    auto isInternetAddressGroup()
    {
        return INTERNET_ADDRESS_IS_GROUP(this._c_internet_address);
    }

    auto toInternetAddressGroup()
    {
        if (!this.is_internet_address_group())
            throw new Exception("Can't convert to message");
        CInternetAddressGroup *iag = INTERNET_ADDRESS_GROUP(this._c_internet_address);
        return mkInternetAddressGroup(iag);
    }

    auto toInternetAddress()
    {
        return cast(InternetAddress)this;
    }
}

InternetAddress mkInternetAddress(CInternetAddress *cia)
{
     return new InternetAddress(cia);
}

/**
    INTERNET ADDRESS LIST
*/

class InternetAddressList
{
    CInternetAddressList *_c_internet_address_list;

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

    auto indexof(InternetAddress ia)
    {
        return internet_address_list_index_of(this._c_internet_address_list, ia._c_internet_address);
    }

    auto getAddress(int idx)
    {
        CInternetAddress *cia = internet_address_list_get_address (this._c_internet_address_list, idx);
        return mk_internet_address(cia);
    }

    string toString(bool encode=true)
    {
        auto ret = internet_address_list_to_string(this._c_internet_address_list, encode);
        if (ret is null)
            return "";
        else
            return ret;
    }

    void append(InternetAddressList other)
    {
        internet_address_list_append(this._c_internet_address_list, other._c_internet_address_list);
    }

    auto add(InternetAddress addr)
    {
        idx = internet_address_list_add (this._c_internet_address_list, addr._c_internet_address);
        return idx;
    }

    void insert(InternetAddress addr, int idx)
    {
        internet_address_list_insert (this._c_internet_address_list, idx, addr._c_internet_address);
    }

    void remove(InternetAddress addr)
    {
        out_bool = internet_address_list_remove (this._c_internet_address_list, addr._c_internet_address);
        if (!out_bool)
            throw new Exception(format("InternetAddressListError: Couldn't remove item %s",addr));
    }

    void removeAt(int idx)
    {
        auto out_bool = internet_address_list_remove_at (this._c_internet_address_list, idx);
        if (!out_bool)
            throw new Exception(format("InternetAddressListError: Couldn't remove item at index %s",idx));
    }
}


InternetAddressList mkInternetAddressList(CInternetAddressList *cial)
{
    auto InternetAddressList ial = new InternetAddressList();
    ial._c_internet_address_list = cial;
    return ial;
}


// Static construction function
auto parseInternetAddressList(char *s)
{
    // A static function that takes a string and returns an InternetAddressList() object.
    CInternetAddressList *cial = internet_address_list_parse_string (s);
    return mk_internet_address_list(cial);
}

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

    this(CInternetAddressMailbox *iam)
    {
        this._c_internet_address_mailbox = iam;
        this._c_internet_address = INTERNET_ADDRESS(iam);
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

InternetAddressMailbox mkInternetAddressMailbox(CInternetAddressMailbox *iam)
{
    return new InternetAddressMailbox(iam);
}

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

    this(CInternetAddressGroup *iag)
    {
        this._c_internet_address_group = iag;
        this._c_internet_address = INTERNET_ADDRESS(iag);
    }

    auto getMembers()
    {
        CInternetAddressList *cial;
        cial = internet_address_group_getMembers(this._c_internet_address_group);
        return mk_internet_address_list(cial);
    }

    auto setMembers(InternetAddressList members)
    {
        internet_address_group_setMembers (this._c_internet_address_group, members._c_internet_address_list);
    }

    auto addMember(InternetAddress member)
    {
        return internet_address_group_add_member (this._c_internet_address_group, member._c_internet_address);
    }
}

InternetAddressGroup mkInternetAddressGroup(CInternetAddressGroup *iag)
{
    return new InternetAddressGroup(iag);
}
