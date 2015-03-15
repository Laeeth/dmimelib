//from libc.stdio cimport fopen, fclose, FILE, stdin, stdout

alias time_t=long;
alias bint=int;

struct guint32;
struct GType;
struct GObject;

struct GByteArray
{
 ubyte *data;
 uint len;

struct GPtrArray;
struct GError
{
    ubyte *message;
}

struct GMimeReferences;

enum GMimeContentEncoding
{
    Default,
    Bit7,
    Bit8,
    Binary,
    Base64,
    QuotedPrintable,
    UUEncode,
}

enum GMimeStreamBufferMode
{
    CacheRead,
    BlockRead,
    BlockWrite,
}

struct GMimeStream;
struct GMimeStreamFilter;
struct GMimeFilter;

struct GMimeDataWrapper;
struct GMimeParser;
struct GMimeObject;
struct GMimePart;
struct GMimeMultipart;
struct GMimeMultipartEncrypted;
struct GMimeMultipartSigned;
struct GMimeMessage;
struct GMimeMessagePart;
struct GMimeContentType;
struct GMimeParam;
struct GMimeContentDisposition;
struct GMimeHeaderList;
struct GMimeHeader;

struct GMimeHeaderIter
{
    GMimeHeaderList *hdrlist;
    GMimeHeader *cursor;
    uint32 version;
}

struct CInternetAddress "InternetAddress":
struct CInternetAddressGroup "InternetAddressGroup": 
struct CInternetAddressMailbox "InternetAddressMailbox":
struct CInternetAddressList "InternetAddressList":
struct GMimeCipherContext:
struct GMimeGpgContext:


enum GMimeCipherHash
{
    Default,
    MD2,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160,
    TIGER192,
    HAVAL5160,
}

enum GMimeSignatureStatus
{
    None,
    Good,
    Bad,
    Unknown
}

enum GMimeSignerStatus
{
    None,
    Good,
    Bad,
    Error,
}

struct GMimeSigner
{
    GMimeSigner *nextl;
    uint status;
    uint errors;
    uint trust;
    ubyte *fingerprint;
    time_t created;
    time_t expires;
    ubyte *keyid;
    ubyte *name;
}

struct GMimeSignatureValidity
{
    GMimeSignatureStatus status;
    GMimeSigner *signers;
    ubyte *details;
}

struct GMimeSession;
struct GMimeSessionSimple;

void (*GMimeSimpleRequestPasswdFunc)(GMimeSession *session, ubyte *prompt, bint secret,ubyte *item,GError **err);
void (*GMimeSimpleForgetPasswdFunc)(GMimeSession *session, ubyte *item,GError **err);
void (*GMimeSimpleIsOnlineFunc) ();
void g_mime_init (int);

time_t g_mime_utils_header_decode_date (ubyte *str, int *tz_offset);
ubyte* g_mime_utils_header_format_date (time_t date, int tz_offset);
ubyte* g_mime_utils_generate_message_id (ubyte *fqdn);
ubyte* g_mime_utils_decode_message_id (ubyte *message_id);
ubyte* g_mime_references_get_message_id (GMimeReferences *ref);
GMimeReferences* g_mime_references_get_next (GMimeReferences *ref);
GMimeReferences* g_mime_references_decode (ubyte *text);
void g_mime_references_append (GMimeReferences **refs, ubyte *msgid);
void g_mime_references_clear (GMimeReferences **refs);
void g_mime_references_free (GMimeReferences *refs);
ubyte* g_mime_utils_header_fold (ubyte *str);
ubyte* g_mime_utils_header_printf (ubyte *format, ...);
ubyte* g_mime_utils_quote_string (ubyte *str);
void g_mime_utils_unquote_string (ubyte *str);
bint g_mime_utils_text_is_8bit (ubyte *text, size_t len);
GMimeContentEncoding g_mime_utils_best_encoding (ubyte *text,size_t len);
ubyte* g_mime_utils_decode_8bit (ubyte *text, size_t len);
ubyte* g_mime_utils_header_decode_text (ubyte *text);
ubyte* g_mime_utils_header_encode_text (ubyte *text);
ubyte* g_mime_utils_header_decode_phrase (ubyte *phrase);
ubyte* g_mime_utils_header_encode_phrase (ubyte *phrase);
ubyte* g_mime_utils_structured_header_fold (ubyte *str);
ubyte* g_mime_utils_unstructured_header_fold (ubyte *str);
GType g_mime_session_get_type ();
GObject *g_object_new (GType object_type, ubyte *first_property_name);
GByteArray *g_byte_array_new ();
GByteArray *g_byte_array_append (GByteArray *array, ubyte *data, int len);
ubyte *g_mime_session_request_passwd (GMimeSession *session, ubyte *prompt, bint secret, ubyte *item, GError **err);
void g_mime_session_forget_passwd (GMimeSession *session, ubyte *item, GError **err);
bint g_mime_session_is_online (GMimeSession *session);
void g_mime_session_simple_set_request_passwd (GMimeSessionSimple *session, void *request_passwd_func);
void g_mime_session_simple_set_forget_passwd (GMimeSessionSimple *session, void *forget_passwd_func);
void g_mime_session_simple_set_is_online (GMimeSessionSimple *session, void *is_online_func);
GMimeCipherContext * g_mime_gpg_context_new (GMimeSession *session, ubyte *path);
bint g_mime_gpg_context_get_always_trust (GMimeGpgContext *ctx)
void g_mime_gpg_context_set_always_trust (GMimeGpgContext *ctx, bint always_trust);
ssize_t g_mime_stream_read (GMimeStream *stream, ubyte *buf, size_t len);
ssize_t g_mime_stream_length (GMimeStream *stream);
int *g_mime_stream_reset (GMimeStream *stream);
long g_mime_stream_tell (GMimeStream *stream);
GMimeStream *g_mime_stream_file_new (FILE*);
GMimeStream *g_mime_stream_fs_new (int fd);
GMimeStream *g_mime_stream_mem_new ();
GMimeStream *g_mime_stream_mem_new_with_byte_array (GByteArray *array);
GByteArray *g_mime_stream_mem_get_byte_array (GMimeStream *stream);
ssize_t g_mime_stream_buffer_gets (GMimeStream *stream, ubyte *buf, size_t max);
GMimeStream* g_mime_stream_buffer_new (GMimeStream *source, GMimeStreamBufferMode mode);
ssize_t g_mime_stream_length (GMimeStream *stream);
void g_mime_stream_flush (GMimeStream *stream);
int g_mime_stream_close (GMimeStream *stream);
GMimeStream* g_mime_stream_filter_new (GMimeStream *stream);
int g_mime_stream_filter_add (GMimeStreamFilter *stream, GMimeFilter *filter);
GMimeFilter* g_mime_filter_crlf_new (bint, bint);
GMimeFilter* g_mime_filter_charset_new (ubyte *from_charset, ubyte *to_charset);
GMimeContentType *g_mime_content_type_new (ubyte*, ubyte*);
GMimeContentType* g_mime_content_type_new_from_string (ubyte *str);
ubyte* g_mime_content_type_to_string (GMimeContentType *mime_type);
ubyte* g_mime_content_type_get_media_type (GMimeContentType *mime_type);
ubyte* g_mime_content_type_get_media_subtype (GMimeContentType *mime_type);
GMimeParam* g_mime_content_type_get_params (GMimeContentType *mime_type);
ubyte* g_mime_content_type_get_parameter (GMimeContentType *mime_type, ubyte *attribute);
GMimeParam* g_mime_param_next (GMimeParam *param);
ubyte* g_mime_param_get_name (GMimeParam *param);
ubyte* g_mime_param_get_value (GMimeParam *param);
GMimeContentDisposition* g_mime_content_disposition_new_from_string (ubyte *str);
ubyte* g_mime_content_disposition_get_disposition (GMimeContentDisposition *disposition);
GMimeParam* g_mime_content_disposition_get_params (GMimeContentDisposition *disposition);
ubyte* g_mime_content_disposition_get_parameter (GMimeContentDisposition *disposition, ubyte *attribute);
ubyte* g_mime_content_disposition_to_string (GMimeContentDisposition *disposition, bint fold);
GMimeHeaderIter* g_mime_header_iter_new ();
bint g_mime_header_iter_first (GMimeHeaderIter *iter);
bint g_mime_header_iter_last (GMimeHeaderIter *iter);
bint g_mime_header_iter_next (GMimeHeaderIter *iter);
bint g_mime_header_iter_prev (GMimeHeaderIter *iter);
bint g_mime_header_iter_is_valid (GMimeHeaderIter *iter);
ubyte* g_mime_header_iter_get_name (GMimeHeaderIter *iter);
ubyte* g_mime_header_iter_get_value (GMimeHeaderIter *iter);
ubyte* g_mime_header_list_get (GMimeHeaderList *headers, ubyte *name);
bint g_mime_header_list_get_iter (GMimeHeaderList *headers, GMimeHeaderIter *iter);
ubyte * internet_address_get_name (CInternetAddress *ia);
void internet_address_set_name (CInternetAddress *ia, ubyte* name);
ubyte * internet_address_to_string (CInternetAddress *ia, bint encode);
CInternetAddress * internet_address_group_new (ubyte *name);
CInternetAddressList * internet_address_group_get_members (CInternetAddressGroup *group);
void internet_address_group_set_members (CInternetAddressGroup *group, CInternetAddressList *members);
int internet_address_group_add_member (CInternetAddressGroup *group, CInternetAddress *member);
CInternetAddress * internet_address_mailbox_new (ubyte *name, ubyte *addr);
byte * internet_address_mailbox_get_addr (CInternetAddressMailbox *mailbox);
void internet_address_mailbox_set_addr (CInternetAddressMailbox *mailbox, ubyte *addr);
CInternetAddressList * internet_address_list_new ();
int internet_address_list_length (CInternetAddressList *list);
void internet_address_list_clear (CInternetAddressList *list);
int internet_address_list_add (CInternetAddressList *list, CInternetAddress *ia);
void internet_address_list_insert (CInternetAddressList *list, int index, CInternetAddress *ia);
bint internet_address_list_remove (CInternetAddressList *list, CInternetAddress *ia);
bint internet_address_list_remove_at (CInternetAddressList *list, int index);
bint internet_address_list_contains (CInternetAddressList *list, CInternetAddress *ia);
int internet_address_list_index_of (CInternetAddressList *list, CInternetAddress *ia);
CInternetAddress * internet_address_list_get_address (CInternetAddressList *list, int index);
void internet_address_list_set_address (CInternetAddressList *list, int index, CInternetAddress *ia);
void internet_address_list_prepend (CInternetAddressList *list, CInternetAddressList *prepend);
void internet_address_list_append (CInternetAddressList *list, CInternetAddressList *append);
byte * internet_address_list_to_string (CInternetAddressList *list, bint encode);
CInternetAddressList * internet_address_list_parse_string (ubyte *str);
void internet_address_list_writer (CInternetAddressList *list, ubyte *str);
GMimeObject *g_mime_object_new (GMimeContentType*);
ubyte *g_mime_object_to_string (GMimeObject *object);
ssize_t *g_mime_object_write_to_stream (GMimeObject *object, GMimeStream *stream);
ubyte* g_mime_object_get_content_type_parameter (GMimeObject *object, ubyte* name);
ubyte* g_mime_object_get_headers (GMimeObject *object);
GMimeHeaderList* g_mime_object_get_header_list (GMimeObject *object);
ubyte* g_mime_message_get_sender (GMimeMessage *message);
ubyte* g_mime_message_get_reply_to (GMimeMessage *message);
ubyte* g_mime_message_get_subject (GMimeMessage *message);
ubyte* g_mime_message_get_date_as_string (GMimeMessage *message);
ubyte* g_mime_message_get_message_id (GMimeMessage *message);
GMimeObject* g_mime_message_get_mime_part (GMimeMessage *message);
GMimeMessagePart* g_mime_message_part_new_with_message (uyte *subtype, GMimeMessage *message);
GMimeMessage* g_mime_message_part_get_message (GMimeMessagePart *part);
int g_mime_multipart_get_count (GMimeMultipart *multipart);
GMimeObject* g_mime_multipart_get_part (GMimeMultipart *multipart, int index);
GMimeObject* g_mime_multipart_get_subpart_from_content_id (GMimeMultipart *multipart, ubyte *content_id);
GMimeMultipartEncrypted * g_mime_multipart_encrypted_new ();
int g_mime_multipart_encrypted_encrypt (GMimeMultipartEncrypted *mpe, GMimeObject *content,
    GMimeCipherContext *ctx, bint sign, ubyte *userid, GPtrArray *recipients, GError **err);
GMimeObject * g_mime_multipart_encrypted_decrypt (GMimeMultipartEncrypted *mpe, GMimeCipherContext *ctx, 
 GError **err);
GMimeSignatureValidity * g_mime_multipart_encrypted_get_signature_validity (GMimeMultipartEncrypted *mpe);
GMimeMultipartSigned * g_mime_multipart_signed_new ();
int g_mime_multipart_signed_sign (GMimeMultipartSigned *mps, GMimeObject *content, GMimeCipherContext *ctx,
    byte *userid, GMimeCipherHash hash, GError **err);
GMimeSignatureValidity * g_mime_multipart_signed_verify (GMimeMultipartSigned *mps, GMimeCipherContext *ctx,
 GError **err);
ubyte * g_mime_part_get_content_description (GMimePart *mime_part);
ubyte * g_mime_part_get_content_id (GMimePart *mime_part);
ubyte * g_mime_part_get_content_md5 (GMimePart *mime_part);
bint g_mime_part_verify_content_md5 (GMimePart *mime_part);
ubyte * g_mime_part_get_content_location (GMimePart *mime_part);
GMimeContentEncoding g_mime_part_get_content_encoding (GMimePart *mime_part);
ubyte * g_mime_part_get_filename (GMimePart *mime_part);
GMimeDataWrapper* g_mime_part_get_content_object (GMimePart *mime_part);
GMimeDataWrapper * g_mime_data_wrapper_new_with_stream (GMimeStream *stream, GMimeContentEncoding encoding);
ssize_t g_mime_data_wrapper_write_to_stream (GMimeDataWrapper *wrapper, GMimeStream *stream);
GMimeParser *g_mime_parser_new_with_stream (GMimeStream*);
GMimeObject *g_mime_parser_construct_part (GMimeParser*);
GMimeMessage *g_mime_parser_construct_message (GMimeParser*);
GMimeStreamFilter *GMIME_STREAM_FILTER (GMimeStream*);
GMimeSession *GMIME_SESSION (GObject*);
bint GMIME_IS_SESSION (GObject*); 
GMimePart *GMIME_PART (GMimeObject*);
bint GMIME_IS_PART (GMimeObject*);
GMimeObject *GMIME_OBJECT (void*);
bint GMIME_IS_MULTIPART (GMimeObject*);
GMimeMultipart *GMIME_MULTIPART (GMimeObject*);
bint GMIME_IS_MULTIPART_ENCRYPTED (GMimeObject*);
GMimeMultipartEncrypted *GMIME_MULTIPART_ENCRYPTED (GMimeObject*);
bint GMIME_IS_MULTIPART_SIGNED (GMimeObject*);
GMimeMultipartSigned *GMIME_MULTIPART_SIGNED (GMimeObject*);
bint GMIME_IS_MESSAGE (GMimeObject*);
GMimeMessage *GMIME_MESSAGE (GMimeObject*);
bint GMIME_IS_MESSAGE_PART (GMimeObject*);
GMimeMessagePart *GMIME_MESSAGE_PART (GMimeObject*);
bint GMIME_IS_CIPHER_CONTEXT (void*);
GMimeCipherContext *GMIME_CIPHER_CONTEXT (void*);
bint GMIME_IS_GPG_CONTEXT (GMimeCipherContext*);
GMimeGpgContext *GMIME_GPG_CONTEXT (GMimeCipherContext*);
GMimeSession *GMIME_SESSION (GObject*);
bint GMIME_IS_SESSION_SIMPLE (GMimeSession*);
GMimeSessionSimple *GMIME_SESSION_SIMPLE (GMimeSession*);
CInternetAddress *INTERNET_ADDRESS (void*);
bint INTERNET_ADDRESS_IS_MAILBOX (CInternetAddress*);
CInternetAddressMailbox *INTERNET_ADDRESS_MAILBOX (CInternetAddress*);
bint INTERNET_ADDRESS_IS_GROUP (CInternetAddress*);
CInternetAddressGroup *INTERNET_ADDRESS_GROUP (CInternetAddress*);
