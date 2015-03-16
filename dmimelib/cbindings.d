//from libc.stdio cimport fopen, fclose, FILE, stdin, stdout
module dmimelib.cbindings;

import std.c.stdio;

alias ssize_t=long;
alias gpointer=void*;

struct guint32 {};
struct GType {};
struct GObject {};
struct GPtrArray {};
struct GMimeStream {};
struct GMimeStreamFilter {};
struct GMimeFilter {};
struct GMimeFilterBasic {};
struct GMimeFilterBest {};
struct GMimeFilterCharset {};
struct GMimeFilterCRLF {};
struct GMimeFilterEnriched {};
struct GMimeFilterFrom {};
struct GMimeFilterMd5 {};
struct GMimeFilterStrip {};
struct GMimeFilterWindows {};
struct GMimeFilterYenc {};
struct GMimeFilterGZip {};
struct GMimeFilterHTML {};
struct GMimeDataWrapper {};
struct GMimeParser {};
struct GMimeObject {};
struct GMimePart {};
struct GMimeMultipart {};
struct GMimeMultipartEncrypted {};
struct GMimeMultipartSigned {};
struct GMimeMessage {};
struct GMimeMessagePart {};
struct GMimeContentType {};
struct GMimeParam {};
struct GMimeContentDisposition {};
struct GMimeHeaderList {};
struct GMimeHeader {};

struct CInternetAddress {};
struct CInternetAddressGroup {};
struct CInternetAddressMailbox {};
struct CInternetAddressList {};
struct GMimeStreamPipe {};
struct GMimeStreamCat {};
struct GMimeSession {};
struct GMimeSessionSimple {};
struct GMimeStreamMem {};
struct GMimeEncodingConstraint {};
struct GMimeStreamFile {};
struct GMimeStreamFs {};
struct GMimeSeekWhence {};
struct GMimeStreamIOVector {};
struct GString {};


enum GMimeFilterFromMode
{
    Default=0,
    Escape=0,
    Armor=1,
}

    
extern(C)
{
    alias time_t=long;
    alias bint=int;


    struct GByteArray
    {
        ubyte *data;
        uint len;
    }

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

    struct GMimeHeaderIter
    {
        GMimeHeaderList *hdrlist;
        GMimeHeader *cursor;
        extern guint32 _version;
    }

    // struct GMimeCipherContext; removed in 2.6
    struct GMimeGpgContext;


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
        Good,
        Error,
        Bad,
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


    alias GMimeSimpleRequestPasswdFunc= void function(GMimeSession *session, ubyte *prompt, bint secret,ubyte *item,GError **err);
    alias GMimeSimpleForgetPasswdFunc=void function(GMimeSession *session, ubyte *item,GError **err);
    alias GMimeSimpleIsOnlineFunc=void function();
    void g_mime_init (int);

    
    /**
        g_mime_utils_
            generate_message_id
            decode_message_id
            header_
                decode_date
                format_date
                fold
                printf
                decode_text
                encode_text
                decode_phrase
                encode_phrase
            quote_string
            unquote_string
            text_is_8bit
            decode_8_bit
            best_encoding
            structured_header_fold
            unstructured_header_fold

    */
    ubyte* g_mime_utils_generate_message_id (ubyte *fqdn);
    ubyte* g_mime_utils_decode_message_id (ubyte *message_id);
    time_t g_mime_utils_header_decode_date (ubyte *str, int *tz_offset);
    ubyte* g_mime_utils_header_format_date (time_t date, int tz_offset);
    ubyte* g_mime_utils_header_fold (ubyte *str);
    ubyte* g_mime_utils_header_printf (ubyte *format, ...);
    ubyte* g_mime_utils_header_decode_text (ubyte *text);
    ubyte* g_mime_utils_header_encode_text (ubyte *text);
    ubyte* g_mime_utils_header_decode_phrase (ubyte *phrase);
    ubyte* g_mime_utils_header_encode_phrase (ubyte *phrase);
    ubyte* g_mime_utils_quote_string (ubyte *str);
    void g_mime_utils_unquote_string (ubyte *str);
    bint g_mime_utils_text_is_8bit (ubyte *text, size_t len);
    ubyte* g_mime_utils_decode_8bit (ubyte *text, size_t len);
    GMimeContentEncoding g_mime_utils_best_encoding (ubyte *text,size_t len);
    ubyte* g_mime_utils_structured_header_fold (ubyte *str);
    ubyte* g_mime_utils_unstructured_header_fold (ubyte *str);

    /**
        g_mime_references_
            get_message_id
            get_next
            decode
            append
            clear
            free
    */
    ubyte* g_mime_references_get_message_id (GMimeReferences *_ref);
    GMimeReferences* g_mime_references_get_next (GMimeReferences *_ref);
    GMimeReferences* g_mime_references_decode (ubyte *text);
    void g_mime_references_append (GMimeReferences **refs, ubyte *msgid);
    void g_mime_references_clear (GMimeReferences **refs);
    void g_mime_references_free (GMimeReferences *refs);

    /**
        g_mime_session_
            get_type
            request_passwd
            forget_passwd
            is_online
            simple_set
                request_passwd
                forget_passwd
                online
    */
    /**
        removed in version 2.6 !

        GType g_mime_session_get_type ();
        ubyte *g_mime_session_request_passwd (GMimeSession *session, ubyte *prompt, bint secret, ubyte *item, GError **err);
        void g_mime_session_forget_passwd (GMimeSession *session, ubyte *item, GError **err);
        bint g_mime_session_is_online (GMimeSession *session);
        void g_mime_session_simple_set_request_passwd (GMimeSessionSimple *session, void *request_passwd_func);
        void g_mime_session_simple_set_forget_passwd (GMimeSessionSimple *session, void *forget_passwd_func);
        void g_mime_session_simple_set_is_online (GMimeSessionSimple *session, void *is_online_func);
    */    
    /**
        gmime_byte_array_new
        g_byte_array_append
    */
    GByteArray *gmime_byte_array_new ();
    GByteArray *g_byte_array_append (GByteArray *array, ubyte *data, int len);
    
    /**
        g_mime_gpg_context_
            new
            get_always_trust
            set_always_trust
            get_auto_key_retrieve
            set_auto_key_retrieve
            get_use_agent
            set_use_agent
    */
    GMimeCryptoContext* g_mime_gpg_context_new(GMimePasswordRequestFunc request_passwd, const(ubyte*) path);
    bint g_mime_gpg_context_get_always_trust(GMimeGpgContext *ctx);
    void g_mime_gpg_context_set_always_trust(GMimeGpgContext *ctx, bint always_trust);
    bint g_mime_gpg_context_get_auto_key_retrieve(GMimeGpgContext *ctx);
    void g_mime_gpg_context_set_auto_key_retrieve(GMimeGpgContext *ctx, bint auto_key_retrieve);
    bint g_mime_gpg_context_get_use_agent(GMimeGpgContext *ctx);
    void g_mime_gpg_context_set_use_agent(GMimeGpgContext *ctx, bint use_agent);

    /**
        g_mime_pkcs7_context_
            new
            get_always_trust
            set_always_trust
    */
    struct GMimePkcs7Context {};
    GMimeCryptoContext* g_mime_pkcs7_context_new(GMimePasswordRequestFunc request_passwd);
    bint g_mime_pkcs7_context_get_always_trust(GMimePkcs7Context *ctx);
    void g_mime_pkcs7_context_set_always_trust(GMimePkcs7Context *ctx, bint always_trust);
    
    /**
        g_mime_stream_
            
            construct
            read
            substream
            set_bounds
            write_string
            printf
            write
            writev
            write_to_stream
            reset
            tell
            file_
                new
                new_with_bounds
                new_for_path
                get_owner
                set_owner
            fs_
                new
                new_with_bounds
                new_for_path
                get_owner
                set_owner
            mem_
                new
                new_with_byte_array
                new_with_buffer
                get_byte_array
                set_byte_array
                get_owner
                set_owner
            mmap_
                new
                new_with_bounds
            buffer_
                gets
                readln
                new
            seek
            length
            flush
            eos
            filter_
                add
                remove
            null_new
            pipe_
                new
                get_owner
                set_owner
            cat_new
            cat_add_source    
    */
    void g_mime_stream_construct(GMimeStream *stream, long start, long end);
    ssize_t g_mime_stream_read (GMimeStream *stream, ubyte *buf, size_t len);
    GMimeStream* g_mime_stream_substream(GMimeStream *stream, long start, long end);
    void g_mime_stream_set_bounds(GMimeStream *stream, long start, long end);
    ssize_t g_mime_stream_write_string(GMimeStream *stream, const(ubyte*) str);
    ssize_t g_mime_stream_printf(GMimeStream *stream, const(ubyte*) fmt, ...);
    ssize_t g_mime_stream_write (GMimeStream *stream, const (ubyte *)buf, size_t len);
    ssize_t g_mime_stream_writev(GMimeStream *stream, GMimeStreamIOVector *vector, size_t count);
    ssize_t g_mime_stream_write_to_stream(GMimeStream *src, GMimeStream *dest);
    int *g_mime_stream_reset (GMimeStream *stream);
    long g_mime_stream_tell (GMimeStream *stream);
    
    GMimeStream* g_mime_stream_file_new (FILE*);
    GMimeStream* g_mime_stream_file_new_with_bounds(FILE *fp, long start, long end);
    GMimeStream *       g_mime_stream_file_new_for_path     (const(ubyte*) path, const(ubyte*) mode);
    bint g_mime_stream_file_get_owner(GMimeStreamFile *stream);
    void g_mime_stream_file_set_owner(GMimeStreamFile *stream, bint owner);
    
    GMimeStream* g_mime_stream_fs_new (int fd);
    GMimeStream* g_mime_stream_fs_new_with_bounds(int fd, long start, long end);
    GMimeStream*  g_mime_stream_fs_new_for_path(const(ubyte*) path, int flags, int mode);
    bint g_mime_stream_fs_get_owner(GMimeStreamFs *stream);
    void g_mime_stream_fs_set_owner(GMimeStreamFs *stream, bint owner);
    
    GMimeStream* g_mime_stream_mem_new ();
    GMimeStream* g_mime_stream_mem_new_with_byte_array (GByteArray *array);
    GMimeStream* g_mime_stream_mem_new_with_buffer(const(ubyte*) buffer, size_t len);
    GByteArray* g_mime_stream_mem_get_byte_array (GMimeStream *stream);
    void g_mime_stream_mem_set_byte_array(GMimeStreamMem *mem, GByteArray *array);
    bint g_mime_stream_mem_get_owner(GMimeStreamMem *mem);
    void g_mime_stream_mem_set_owner(GMimeStreamMem *mem, bint owner);
    GMimeStream* g_mime_stream_mmap_new(int fd, int prot, int flags);
    GMimeStream* g_mime_stream_mmap_new_with_bounds(int fd, int prot, int flags, long start, long end);

    ssize_t g_mime_stream_buffer_gets (GMimeStream *stream, ubyte *buf, size_t max);
    void g_mime_stream_buffer_readln(GMimeStream *stream, GByteArray *buffer);
    GMimeStream* g_mime_stream_buffer_new (GMimeStream *source, GMimeStreamBufferMode mode);

    long g_mime_stream_seek(GMimeStream *stream, long offset, GMimeSeekWhence whence);
    long g_mime_stream_length (GMimeStream *stream);
    void g_mime_stream_flush (GMimeStream *stream);
    bint g_mime_stream_eos(GMimeStream *stream);
    int g_mime_stream_close (GMimeStream *stream);
    GMimeStream* g_mime_stream_filter_new (GMimeStream *stream);
    int g_mime_stream_filter_add (GMimeStreamFilter *stream, GMimeFilter *filter);
    void g_mime_stream_filter_remove(GMimeStreamFilter *stream, int id);
    GMimeStream* g_mime_stream_null_new();
    GMimeStream* g_mime_stream_pipe_new(int fd);
    bint g_mime_stream_pipe_get_owner(GMimeStreamPipe *stream);
    void g_mime_stream_pipe_set_owner(GMimeStreamPipe *stream, bint owner);
    GMimeStream* g_mime_stream_cat_new();
    int g_mime_stream_cat_add_source(GMimeStreamCat *cat, GMimeStream *source);

/**
    g_mime_filter_
        crlf_new
        charset_new
        html_new
        md5_new
        md5_get_digest
        strip_new
        windows_new
        windows_is_windows_charset
        windows_real_charset
        yenc_
            new
            set_state
            set_crc
            get_crc
            get_pcrc
        copy
        filter
        complete
        reset
        backup
        set_size
        basic_new
        best_new
        best_charset
        best_encoding
        charset_new
        crlf_new
        enriched_new
        from_new
        gzip_new

*/
    
    enum GmimeFilterHtml
    {
        Pre=(1 << 0),                // Wrap stream in <pre> tags.
        ConvertNL=(1 << 1),          // Convert new-lines ('\n') into <br> tags.
        ConvertSpaces=(1 << 2),      // Preserve whitespace by converting spaces into their appropriate html entities.
        ConvertURLs=(1 << 3),        // Wrap detected URLs in <a href=...> tags.
        MarkCitation= (1 << 4),      // Change the colour of citation text.
        ConvertAddresses=(1 << 5),   // Wrap email addresses in "mailto:" href tags.
        Escape8Bit = (1 << 6),       // Converts 8bit characters to '?'.
        Cite= (1 << 7),              // Cites text by prepending "> " to each cited line.
    }

    GMimeFilter* g_mime_filter_crlf_new (bint, bint);
    GMimeFilter* g_mime_filter_charset_new(ubyte *from_charset, ubyte *to_charset);
    GMimeFilter* g_mime_filter_html_new(guint32 flags, guint32 colour);
    GMimeFilter* g_mime_filter_md5_new();
    void g_mime_filter_md5_get_digest(GMimeFilterMd5 *md5, ubyte[16] digest);
    GMimeFilter* g_mime_filter_strip_new();
    GMimeFilter* g_mime_filter_windows_new(const (ubyte *)claimed_charset);
    bint g_mime_filter_windows_is_windows_charset(GMimeFilterWindows *filter);
    const(ubyte*) g_mime_filter_windows_real_charset(GMimeFilterWindows *filter);
    GMimeFilter* g_mime_filter_yenc_new(bint encode);
    void g_mime_filter_yenc_set_state(GMimeFilterYenc *yenc, int state);
    void g_mime_filter_yenc_set_crc(GMimeFilterYenc *yenc, guint32 crc);
    guint32 g_mime_filter_yenc_get_crc(GMimeFilterYenc *yenc);
    guint32 g_mime_filter_yenc_get_pcrc(GMimeFilterYenc *yenc);
    GMimeFilter* g_mime_filter_copy(GMimeFilter *filter);
    void g_mime_filter_filter(GMimeFilter *filter, ubyte *inbuf, size_t inlen, size_t prespace, ubyte**outbuf, size_t *outlen, size_t *outprespace);
    void g_mime_filter_complete(GMimeFilter *filter, ubyte *inbuf, size_t inlen, size_t prespace, ubyte **outbuf, size_t *outlen, size_t *outprespace);
    void g_mime_filter_reset(GMimeFilter *filter);
    void g_mime_filter_backup(GMimeFilter *filter, const (ubyte*) data, size_t length);
    void g_mime_filter_set_size(GMimeFilter *filter, size_t size, bint keep);
    GMimeFilter* g_mime_filter_basic_new(GMimeContentEncoding encoding, bint encode);
    
    enum GMimeFilterBestFlags
    {
        Charset  = (1 << 0),
        Encoding = (1 << 1)
    }
    GMimeFilter* g_mime_filter_best_new(GMimeFilterBestFlags flags);
    const (ubyte*) g_mime_filter_best_charset(GMimeFilterBest *best);
    GMimeContentEncoding g_mime_filter_best_encoding(GMimeFilterBest *best, GMimeEncodingConstraint constraint);
    GMimeFilter* g_mime_filter_charset_new(const (ubyte *)from_charset, const (ubyte*)to_charset);
    GMimeFilter* g_mime_filter_crlf_new(bint encode, bint dots);
    
    enum GmimeFilterEnrichedIsRichtext= (1 << 0);
    GMimeFilter* g_mime_filter_enriched_new(guint32 flags);
    
    GMimeFilter* g_mime_filter_from_new(GMimeFilterFromMode mode);
    
    enum GMimeFilterGZipMode
    {
        Zip,
        Unzip,
    }
    GMimeFilter* g_mime_filter_gzip_new(GMimeFilterGZipMode mode, int level);

    
    /**
        g_mime_content_type_
            new
            new_from_string
            to_string
            is_type
            get_media_type
            set_media_type
            get_media_subtype
            set_media_subtype
            get_params
            set_params
            get_parameter
            set_parameter
    */

    GMimeContentType *g_mime_content_type_new (ubyte*, ubyte*);
    GMimeContentType* g_mime_content_type_new_from_string (ubyte *str);
    ubyte* g_mime_content_type_to_string (GMimeContentType *mime_type);
    bint            g_mime_content_type_is_type         (GMimeContentType *mime_type, const(ubyte*) type, const(ubyte*) subtype);
    ubyte* g_mime_content_type_get_media_type (GMimeContentType *mime_type);
    void                g_mime_content_type_set_media_type  (GMimeContentType *mime_type, const(ubyte*) type);
    ubyte* g_mime_content_type_get_media_subtype (GMimeContentType *mime_type);
    void                g_mime_content_type_set_media_subtype (GMimeContentType *mime_type, const(ubyte*) subtype);
    GMimeParam* g_mime_content_type_get_params (GMimeContentType *mime_type);
    void                g_mime_content_type_set_params      (GMimeContentType *mime_type, GMimeParam *params);
    ubyte* g_mime_content_type_get_parameter (GMimeContentType *mime_type, ubyte *attribute);
    void                g_mime_content_type_set_parameter   (GMimeContentType *mime_type, const(ubyte*) attribute, const(ubyte*) value);

    /**
        g_mime_param_
            new
            new_from_string
            destroy
            next
            get_name
            get_value
            append
            append_param
            write_to_string
    */
    GMimeParam *        g_mime_param_new                    (const(ubyte*) name, const(ubyte*) value); 
    GMimeParam *        g_mime_param_new_from_string        (const(ubyte*) str);
    void                g_mime_param_destroy                (GMimeParam *param);
    const(GMimeParam*)  g_mime_param_next                   (const (GMimeParam *)param);
    const(ubyte*)         g_mime_param_get_name               (const (GMimeParam *)param);
    const(ubyte*)         g_mime_param_get_value              (const (GMimeParam *)param);
    GMimeParam *        g_mime_param_append                 (GMimeParam *params, const(ubyte*) name, const(ubyte*) value);
    GMimeParam *        g_mime_param_append_param           (GMimeParam *params, GMimeParam *param);
    void                g_mime_param_write_to_string        (const (GMimeParam *)param, bint fold, GString *str);

    /**
        g_mime_content_disposition_
            new
            new_from_string
            set_disposition
            get_disposition
            get_params
            set_params
            get_parameter
            set_parameter
            to_string
    */
    
    enum GMimeDispositionAttachment="attachment";
    enum GMimeDispositionInline="inline";
    GMimeContentDisposition * g_mime_content_disposition_new ();
    GMimeContentDisposition * g_mime_content_disposition_new_from_string (const(ubyte*) str);
    void                g_mime_content_disposition_set_disposition (GMimeContentDisposition *disposition, const(ubyte*) value);
    const(ubyte*)         g_mime_content_disposition_get_disposition (GMimeContentDisposition *disposition);
    const(GMimeParam *)  g_mime_content_disposition_get_params (GMimeContentDisposition *disposition);
    void                g_mime_content_disposition_set_params (GMimeContentDisposition *disposition, GMimeParam *params);
    void                g_mime_content_disposition_set_parameter (GMimeContentDisposition *disposition, const(ubyte*) attribute, const(ubyte*) value);
    const(ubyte*)         g_mime_content_disposition_get_parameter (GMimeContentDisposition *disposition, const(ubyte*) attribute);
    ubyte*               g_mime_content_disposition_to_string (GMimeContentDisposition *disposition, bint fold);
    
    /**
        g_mime_header_iter_
            new
            free
            copy
            copy_to
            equal
            first
            last
            next
            prev
            is_valid
            get_name
            get_value
            set_value
            GMimeHeaderWriter
            GMimeHeaderForeachFunc
            remove
    */
    GMimeHeaderIter *   g_mime_header_iter_new              ();
    void                g_mime_header_iter_free             (GMimeHeaderIter *iter);
    GMimeHeaderIter *   g_mime_header_iter_copy             (GMimeHeaderIter *iter);
    void                g_mime_header_iter_copy_to          (GMimeHeaderIter *src, GMimeHeaderIter *dest);
    bint            g_mime_header_iter_equal            (GMimeHeaderIter *iter1, GMimeHeaderIter *iter2);
    bint            g_mime_header_iter_first            (GMimeHeaderIter *iter);
    bint            g_mime_header_iter_last             (GMimeHeaderIter *iter);
    bint            g_mime_header_iter_next             (GMimeHeaderIter *iter);
    bint            g_mime_header_iter_prev             (GMimeHeaderIter *iter);
    bint            g_mime_header_iter_is_valid         (GMimeHeaderIter *iter);
    const(ubyte*)         g_mime_header_iter_get_name         (GMimeHeaderIter *iter);
    const(ubyte*)         g_mime_header_iter_get_value        (GMimeHeaderIter *iter);
    bint            g_mime_header_iter_set_value        (GMimeHeaderIter *iter, const(ubyte*) value);
    alias GMimeHeaderWriter= ssize_t function(GMimeStream *stream, const(ubyte*) name, const(ubyte*) value);
    alias GMimeHeaderForeachFunc = void function(const(ubyte*) name, const(ubyte*) value, gpointer user_data);
    bint            g_mime_header_iter_remove           (GMimeHeaderIter *iter);
    /**
        g_mime_header_list_
            new
            destroy
            clear
            contains
            prepend
            append
            remove
            set
            get
            get_iter
            foreach
            register_writer 
            write_to_stream
            to_string
            get_stream
            set_stream
            get_name
            set_name
    */
    GMimeHeaderList *   g_mime_header_list_new              ();
    void                g_mime_header_list_destroy          (GMimeHeaderList *headers);
    void                g_mime_header_list_clear            (GMimeHeaderList *headers);
    bint            g_mime_header_list_contains         (const GMimeHeaderList *headers, const(ubyte*) name);
    void                g_mime_header_list_prepend          (GMimeHeaderList *headers, const(ubyte*) name, const(ubyte*) value);
    void                g_mime_header_list_append           (GMimeHeaderList *headers, const(ubyte*) name, const(ubyte*) value);
    bint            g_mime_header_list_remove           (GMimeHeaderList *headers, const(ubyte*) name);
    void                g_mime_header_list_set              (GMimeHeaderList *headers, const(ubyte*) name, const(ubyte*) value);
    ubyte* g_mime_header_list_get (GMimeHeaderList *headers, ubyte *name);
    bint g_mime_header_list_get_iter (GMimeHeaderList *headers, GMimeHeaderIter *iter);
    void                g_mime_header_list_foreach          (const GMimeHeaderList *headers, GMimeHeaderForeachFunc func, gpointer user_data);
    void                g_mime_header_list_register_writer  (GMimeHeaderList *headers, const(ubyte*) name, GMimeHeaderWriter writer);
    ssize_t             g_mime_header_list_write_to_stream  (const GMimeHeaderList *headers, GMimeStream *stream);
    ubyte*               g_mime_header_list_to_string        (const GMimeHeaderList *headers);
    GMimeStream *       g_mime_header_list_get_stream       (GMimeHeaderList *headers);
    void                g_mime_header_list_set_stream       (GMimeHeaderList *headers, GMimeStream *stream);
    

    /**
        internet_address_
            to_string
            get_name
            set_name
            group_
                new
                get_members
                set_members
                add_member
            mailbox_
                new
                get_addr
                set_addr
            list_
                new
                length
                clear
                add
                insert
                remove
                remove_at
                contains
                index_of
                get_address
                set_address
                prepend
                append
                to_string
                parse_string
                writer
    */

    ubyte * internet_address_to_string (CInternetAddress *ia, bint encode);
    const(ubyte*)         internet_address_get_name           (CInternetAddress *ia);
    void                internet_address_set_name           (CInternetAddress *ia, const(ubyte*) name);
    CInternetAddress * internet_address_group_new (ubyte *name);
    CInternetAddressList * internet_address_group_get_members (CInternetAddressGroup *group);
    void internet_address_group_set_members (CInternetAddressGroup *group, CInternetAddressList *members);
    int internet_address_group_add_member (CInternetAddressGroup *group, CInternetAddress *member);
    CInternetAddress * internet_address_mailbox_new (ubyte *name, ubyte *addr);
    ubyte * internet_address_mailbox_get_addr (CInternetAddressMailbox *mailbox);
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
    ubyte * internet_address_list_to_string (CInternetAddressList *list, bint encode);
    CInternetAddressList * internet_address_list_parse_string (ubyte *str);
    void internet_address_list_writer (CInternetAddressList *list, ubyte *str);

    /**
        g_mime_object_
            GMimeObjectForEachFunc
            register_type
            new
            new_type
            set_content_type
            get_content_type
            set_content_type_parameter
            get_content_type_parameter
            set_disposition
            get_disposition
            set_content_disposition
            get_content_disposition
            set_content_disposition_parameter
            get_content_disposition_parameter
            set_content_id
            get_content_id
            prepend_header
            append_header
            remove_header
            set_header
            get_header
            get_headers
            get_header_list
            write_to_stream
            to_string
            encode
    */
    
    alias GMimeObjectForeachFunc=void                function(GMimeObject *parent, GMimeObject *part, gpointer user_data);
    void                g_mime_object_register_type         (const(ubyte*) type, const(ubyte*) subtype, GType object_type);
    GMimeObject *       g_mime_object_new                   (GMimeContentType *content_type);
    GMimeObject *       g_mime_object_new_type              (const(ubyte*) type, const(ubyte*) subtype);
    void                g_mime_object_set_content_type      (GMimeObject *object, GMimeContentType *content_type);
    GMimeContentType *  g_mime_object_get_content_type      (GMimeObject *object);
    void                g_mime_object_set_content_type_parameter (GMimeObject *object, const(ubyte*) name, const(ubyte*) value);
    const(ubyte*)         g_mime_object_get_content_type_parameter (GMimeObject *object, const(ubyte*) name); 
    void                g_mime_object_set_disposition       (GMimeObject *object, const(ubyte*) disposition);
    const(ubyte*)         g_mime_object_get_disposition       (GMimeObject *object);
    void                g_mime_object_set_content_disposition (GMimeObject *object, GMimeContentDisposition *disposition);
    GMimeContentDisposition * g_mime_object_get_content_disposition (GMimeObject *object); 
    void                g_mime_object_set_content_disposition_parameter (GMimeObject *object, const(ubyte*) attribute, const(ubyte*) value);
    const(ubyte*)         g_mime_object_get_content_disposition_parameter (GMimeObject *object, const(ubyte*) attribute);
    void                g_mime_object_set_content_id        (GMimeObject *object, const(ubyte*) content_id);
    const(ubyte*)         g_mime_object_get_content_id        (GMimeObject *object);
    void                g_mime_object_prepend_header        (GMimeObject *object, const(ubyte*) header, const(ubyte*) value);
    void                g_mime_object_append_header         (GMimeObject *object, const(ubyte*) header, const(ubyte*) value);
    bint            g_mime_object_remove_header         (GMimeObject *object, const(ubyte*) header);
    void                g_mime_object_set_header            (GMimeObject *object, const(ubyte*) header, const(ubyte*) value);
    const(ubyte*)         g_mime_object_get_header            (GMimeObject *object, const(ubyte*) header);
    ubyte*               g_mime_object_get_headers           (GMimeObject *object);
    GMimeHeaderList *   g_mime_object_get_header_list       (GMimeObject *object);
    ssize_t             g_mime_object_write_to_stream       (GMimeObject *object, GMimeStream *stream);
    ubyte*               g_mime_object_to_string             (GMimeObject *object);
    void                g_mime_object_encode                (GMimeObject *object, GMimeEncodingConstraint constraint);
    /**
        g_mime_message_
            new
            set_sender 
            get_sender 
            set_reply_to 
            get_reply_to 
            add_recipient 
            get_recipients 
            get_all_recipients 
            set_subject 
            get_subject 
            set_date 
            get_date 
            set_date_as_string 
            get_date_as_string 
            set_message_id 
            get_message_id 
            set_mime_part 
            get_mime_part 
            foreach
            get_body     
    */
    enum GMimeRecipientType
    {
        To,
        CC,
        BCC,
    }

    GMimeMessage *      g_mime_message_new                  (bint pretty_headers);
    void                g_mime_message_set_sender           (GMimeMessage *message, const(ubyte*) sender);
    const(ubyte*)         g_mime_message_get_sender           (GMimeMessage *message);
    void                g_mime_message_set_reply_to         (GMimeMessage *message, const(ubyte*) reply_to);
    const(ubyte*)         g_mime_message_get_reply_to         (GMimeMessage *message);
    void                g_mime_message_add_recipient        (GMimeMessage *message, GMimeRecipientType type, const(ubyte*) name, const(ubyte*) addr);
    CInternetAddressList * g_mime_message_get_recipients     (GMimeMessage *message, GMimeRecipientType type);
    CInternetAddressList * g_mime_message_get_all_recipients (GMimeMessage *message);
    void                g_mime_message_set_subject          (GMimeMessage *message, const(ubyte*) subject);
    const(ubyte*)         g_mime_message_get_subject          (GMimeMessage *message);
    void                g_mime_message_set_date             (GMimeMessage *message, time_t date, int tz_offset);
    void                g_mime_message_get_date             (GMimeMessage *message, time_t *date, int *tz_offset);
    void                g_mime_message_set_date_as_string   (GMimeMessage *message, const(ubyte*) str);
    ubyte*               g_mime_message_get_date_as_string   (GMimeMessage *message);
    void                g_mime_message_set_message_id       (GMimeMessage *message, const(ubyte*) message_id);
    const(ubyte*)         g_mime_message_get_message_id       (GMimeMessage *message);
    void                g_mime_message_set_mime_part        (GMimeMessage *message, GMimeObject *mime_part);
    GMimeObject *       g_mime_message_get_mime_part        (GMimeMessage *message);
    void                g_mime_message_foreach              (GMimeMessage *message, GMimeObjectForeachFunc callback, gpointer user_data);
    GMimeObject *       g_mime_message_get_body             (GMimeMessage *message);

/**
    g_mime_message_part_
            new
            new_with_message
            get_message
            set_message
*/
    GMimeMessagePart* g_mime_message_part_new(const (ubyte*)subtype);
    GMimeMessagePart* g_mime_message_part_new_with_message (ubyte *subtype, GMimeMessage *message);
    GMimeMessage* g_mime_message_part_get_message (GMimeMessagePart *part);
    void g_mime_message_part_set_message(GMimeMessagePart *part, GMimeMessage *message);
    
    /**
        g_mime_message_partial_
            get_id
            get_number
            get_total
            reconstruct_message
            split_message
    */
    struct GMimeMessagePartial {};
    GMimeMessagePartial* g_mime_message_partial_new(const (ubyte*) id, int number, int total);
    const (ubyte*) g_mime_message_partial_get_id(GMimeMessagePartial *partial);
    int g_mime_message_partial_get_number(GMimeMessagePartial *partial);
    int g_mime_message_partial_get_total(GMimeMessagePartial *partial);
    GMimeMessage* g_mime_message_partial_reconstruct_message(GMimeMessagePartial **partials, size_t num);
    GMimeMessage** g_mime_message_partial_split_message(GMimeMessage *message, size_t max_size, size_t *nparts);
    
    /**
        g_mime_part_iter_
            new
            free
            reset
            jump_to
            is_valid
            next
            prev
            get_
                toplevel
                current
                parent
                path
            replace
            remove
    */
    struct GMimePartIter {};
    GMimePartIter* g_mime_part_iter_new(GMimeObject *toplevel);
    void  g_mime_part_iter_free(GMimePartIter *iter);
    void g_mime_part_iter_reset(GMimePartIter *iter);
    bint g_mime_part_iter_jump_to(GMimePartIter *iter, const(ubyte*) path);
    bint g_mime_part_iter_is_valid(GMimePartIter *iter);
    bint g_mime_part_iter_next(GMimePartIter *iter);
    bint g_mime_part_iter_prev(GMimePartIter *iter);
    GMimeObject* g_mime_part_iter_get_toplevel(GMimePartIter *iter);
    GMimeObject* g_mime_part_iter_get_current(GMimePartIter *iter);
    GMimeObject* g_mime_part_iter_get_parent(GMimePartIter *iter);
    ubyte* g_mime_part_iter_get_path(GMimePartIter *iter);
    bint g_mime_part_iter_replace(GMimePartIter *iter, GMimeObject *replacement);
    bint g_mime_part_iter_remove(GMimePartIter *iter);
    /**
            g_mime_multipart_
                encrypted_
                    new
                    encrypt
                    decrypt
                    get_signature_validity
                signed_
                    new
                    sign
                    verify
                new
                new_with_subtype
                set_preface
                get_preface
                set_postface
                get_postface
                set_boundary
                get_boundary
                get_count
                contains
                index_of
                add
                clear
                insert
                remove_at
                replace
                get_part
                foreach
                get_subpart_from_content_id
    */
    GMimeMultipartEncrypted * g_mime_multipart_encrypted_new ();
    int g_mime_multipart_encrypted_encrypt  (GMimeMultipartEncrypted *mpe, GMimeObject *content, GMimeCryptoContext *ctx, bint sign,
        const (ubyte*) userid, GMimeDigestAlgo digest, GPtrArray *recipients, GError **err);
    GMimeObject* g_mime_multipart_encrypted_decrypt(GMimeMultipartEncrypted *mpe, GMimeCryptoContext *ctx, GMimeDecryptResult **result, GError **err);
    GMimeSignatureValidity * g_mime_multipart_encrypted_get_signature_validity (GMimeMultipartEncrypted *mpe);
    GMimeMultipartSigned * g_mime_multipart_signed_new ();
    
    /**
        CipherContext removed in 2.6
        int g_mime_multipart_signed_sign (GMimeMultipartSigned *mps, GMimeObject *content, GMimeCipherContext *ctx, byte *userid, GMimeCipherHash hash, GError **err);
        GMimeSignatureValidity * g_mime_multipart_signed_verify (GMimeMultipartSigned *mps, GMimeCipherContext *ctx, GError **err);
    */
    GMimeMultipart* g_mime_multipart_new();
    GMimeMultipart* g_mime_multipart_new_with_subtype(const(ubyte*) subtype);
    void g_mime_multipart_set_preface(GMimeMultipart *multipart, const(ubyte*) preface);
    const(ubyte*)  g_mime_multipart_get_preface(GMimeMultipart *multipart);
    void g_mime_multipart_set_postface(GMimeMultipart *multipart, const(ubyte*) postface);
    const(ubyte*)  g_mime_multipart_get_postface(GMimeMultipart *multipart);
    void g_mime_multipart_set_boundary(GMimeMultipart *multipart, const(ubyte*) boundary);
    const(ubyte*)  g_mime_multipart_get_boundary(GMimeMultipart *multipart);
    int g_mime_multipart_get_count(GMimeMultipart *multipart);
    bint g_mime_multipart_contains(GMimeMultipart *multipart, GMimeObject *part);
    int g_mime_multipart_index_of(GMimeMultipart *multipart, GMimeObject *part);
    void g_mime_multipart_add(GMimeMultipart *multipart, GMimeObject *part);
    void g_mime_multipart_clear(GMimeMultipart *multipart);
    void g_mime_multipart_insert(GMimeMultipart *multipart, int index, GMimeObject *part);
    bint g_mime_multipart_remove(GMimeMultipart *multipart, GMimeObject *part);
    GMimeObject* g_mime_multipart_remove_at(GMimeMultipart *multipart, int index);
    GMimeObject* g_mime_multipart_replace(GMimeMultipart *multipart, int index, GMimeObject *replacement);
    GMimeObject* g_mime_multipart_get_part(GMimeMultipart *multipart, int index);
    void g_mime_multipart_foreach(GMimeMultipart *multipart, GMimeObjectForeachFunc callback, gpointer user_data);
    GMimeObject* g_mime_multipart_get_subpart_from_content_id (GMimeMultipart *multipart, const(ubyte*) content_id);

    /**
        g_mime_part_
            new
            new_with_type
            set_content_description
            get_content_description
            set_content_id
            get_content_id
            set_content_md5
            get_content_md5
            verify_content_md5
            set_conent_location
            get_content_location
            set_content_encoding
            get_content_encoding
            get_best_content_encoding
            set_filename
            get_filename
            get_content_object
            set_content_object
    */
    GMimePart* g_mime_part_new();
    GMimePart* g_mime_part_new_with_type(const(ubyte*) type, const(ubyte*) subtype);
    void g_mime_part_set_content_description(GMimePart *mime_part, const(ubyte*) description);
    const(ubyte*)  g_mime_part_get_content_description(GMimePart *mime_part);
    void g_mime_part_set_content_id(GMimePart *mime_part, const(ubyte*) content_id);
    const(ubyte*)  g_mime_part_get_content_id(GMimePart *mime_part);
    void g_mime_part_set_content_md5(GMimePart *mime_part, const(ubyte*) content_md5);
    const(ubyte*)  g_mime_part_get_content_md5(GMimePart *mime_part);
    bint g_mime_part_verify_content_md5(GMimePart *mime_part);
    void g_mime_part_set_content_location(GMimePart *mime_part, const(ubyte*) content_location);
    const(ubyte*)  g_mime_part_get_content_location(GMimePart *mime_part);
    void g_mime_part_set_content_encoding(GMimePart *mime_part, GMimeContentEncoding encoding);
    GMimeContentEncoding g_mime_part_get_content_encoding(GMimePart *mime_part);
    GMimeContentEncoding g_mime_part_get_best_content_encoding(GMimePart *mime_part, GMimeEncodingConstraint constraint); 
    void g_mime_part_set_filename(GMimePart *mime_part, const(ubyte*) filename);
    const(ubyte*)  g_mime_part_get_filename(GMimePart *mime_part);
    GMimeDataWrapper*  g_mime_part_get_content_object(GMimePart *mime_part);
    void g_mime_part_set_content_object(GMimePart *mime_part, GMimeDataWrapper *content);
    /**
        g_mime_data_wrapper_
            new_with_stream
            write_to_stream
            new
            set_stream
            get_stream
            set_encoding
            get_encoding
    */
    GMimeDataWrapper * g_mime_data_wrapper_new_with_stream(GMimeStream *stream, GMimeContentEncoding encoding);
    ssize_t g_mime_data_wrapper_write_to_stream(GMimeDataWrapper *wrapper, GMimeStream *stream);
    GMimeDataWrapper* g_mime_data_wrapper_new();
    void g_mime_data_wrapper_set_stream(GMimeDataWrapper *wrapper, GMimeStream *stream);
    GMimeStream* g_mime_data_wrapper_get_stream(GMimeDataWrapper *wrapper);
    void g_mime_data_wrapper_set_encoding(GMimeDataWrapper *wrapper, GMimeContentEncoding encoding);
    GMimeContentEncoding g_mime_data_wrapper_get_encoding   (GMimeDataWrapper *wrapper);

    /**
        GMimeParserHeaderRegexFunc
        g_mime_parser_
            new
            new_with_stream
            init_with_stream
            get_persist_stream
            set_persist_stream
            get_scan_from
            set_scan_from
            get_respect_content_length
            set_respect_content_length
            set_header_regex
            tell
            eos
            construct_part
            construct_message
            get_
                from
                from_offset
                headers_begin
                headers_end
    */
    alias GMimeParserHeaderRegexFunc = void function(GMimeParser *parser, const(ubyte*) header, const(ubyte*) value, long offset, gpointer user_data);
    GMimeParser* g_mime_parser_new();
    GMimeParser* g_mime_parser_new_with_stream(GMimeStream *stream);
    void g_mime_parser_init_with_stream(GMimeParser *parser, GMimeStream *stream);
    bint g_mime_parser_get_persist_stream(GMimeParser *parser);
    void g_mime_parser_set_persist_stream(GMimeParser *parser, bint persist);
    bint g_mime_parser_get_scan_from(GMimeParser *parser);
    void g_mime_parser_set_scan_from(GMimeParser *parser, bint scan_from);
    bint g_mime_parser_get_respect_content_length(GMimeParser *parser);
    void g_mime_parser_set_respect_content_length(GMimeParser *parser, bint respect_content_length);
    void g_mime_parser_set_header_regex(GMimeParser *parser, const(ubyte*) regex, GMimeParserHeaderRegexFunc header_cb, gpointer user_data);
    long g_mime_parser_tell(GMimeParser *parser);
    bint g_mime_parser_eos(GMimeParser *parser);
    GMimeObject* g_mime_parser_construct_part(GMimeParser *parser);
    GMimeMessage* g_mime_parser_construct_message(GMimeParser *parser);
    ubyte*  g_mime_parser_get_from(GMimeParser *parser);
    long g_mime_parser_get_from_offset(GMimeParser *parser);
    long g_mime_parser_get_headers_begin(GMimeParser *parser);
    long g_mime_parser_get_headers_end(GMimeParser *parser);
    
    /**
        GMIME
    */
    GMimeStreamFilter *GMIME_STREAM_FILTER (GMimeStream*);
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
    // bint GMIME_IS_CIPHER_CONTEXT (void*); removed in 2.6
    // GMimeCipherContext *GMIME_CIPHER_CONTEXT (void*); removed in 2.6
    // bint GMIME_IS_GPG_CONTEXT (GMimeCipherContext*);
    // GMimeGpgContext *GMIME_GPG_CONTEXT (GMimeCipherContext*); removed in 2.6
    GMimeSession *GMIME_SESSION (GObject*);
    bint GMIME_IS_SESSION_SIMPLE (GMimeSession*);
    GMimeSessionSimple *GMIME_SESSION_SIMPLE (GMimeSession*);
    CInternetAddress *INTERNET_ADDRESS (void*);
    bint INTERNET_ADDRESS_IS_MAILBOX (CInternetAddress*);
    CInternetAddressMailbox *INTERNET_ADDRESS_MAILBOX (CInternetAddress*);
    bint INTERNET_ADDRESS_IS_GROUP (CInternetAddress*);
    CInternetAddressGroup *INTERNET_ADDRESS_GROUP (CInternetAddress*);


/**
    g_mime_
        ydecode_step
        yencode_step 
        yencode_close
*/
    enum GMIME_YENCODE
    {
        CRC_INIT       =~0, // Initial state for the crc and pcrc state variables.
        STATE_INIT      =0, // Initial state for the g_mime_ydecode_step() function.
    }
    //Gets the final crc value from crc. crc :crc or pcrc state variable
    long GMIME_YENCODE_CRC_FINAL(long crc)
    {
        return ~crc;
    }
    enum GIMIME_YDECODE
    {
        STATE_INIT      = 0,        // Initial state for the g_mime_ydecode_step() function.
        STATE_EOLN     =(1 << 8),   // State bit that denotes the yEnc filter has reached an end-of-line. This state is for internal use only.
        STATE_ESCAPE    = (1 << 9), // State bit that denotes the yEnc filter has reached an escape sequence. This state is for internal use only.
        STATE_END       = 1 << 15,  // State bit that denoates that g_mime_ydecode_step() has finished decoding.
        STATE_BEGIN     = (1 << 12), // State bit that denotes the yEnc filter has found the =ybegin line.
        STATE_DECODE    =   (1 << 14), // State bit that denotes yEnc filter has begun decoding the actual yencoded content and will continue to
                                    // do so until an =yend line is found (or until there is nothing left to decode).
        STATE_PART     = (1 << 13),
    }

    size_t g_mime_ydecode_step(const(ubyte*) inbuf, size_t inlen, ubyte *outbuf, int *state, guint32 *pcrc, guint32 *crc);
    size_t g_mime_yencode_step(const(ubyte*) inbuf, size_t inlen, ubyte *outbuf, int *state, guint32 *pcrc, guint32 *crc);
    size_t g_mime_yencode_close(const(ubyte*) inbuf, size_t inlen, ubyte *outbuf, int *state, guint32 *pcrc, guint32 *crc);



    enum GMimePubKeyAlgo
    {
        Default  = 0,
        RSA      = 1,
        RSA_E    = 2,
        RSA_S    = 3,
        ELG_E    = 16,
        DSA      = 17,
        ELG      = 20,
    }

    enum GMimeDigestAlgo
    {
        DEFAULT     = 0,
        MD5         = 1,
        SHA1        = 2,
        RIPEMD160   = 3,
        MD2         = 5,
        TIGER192    = 6,
        HAVAL5160   = 7,
        SHA256      = 8,
        SHA384      = 9,
        SHA512      = 10,
        SHA224      = 11,
        MD4         = 301
    }

    enum GMimeCertificateTrust
    {
        None,
        Never,
        Undefined,
        Marginal,
        Fully,
        Ultimate,
    }

    struct GMimeCertificate {};
    struct GMimeCertificateList{};

    GMimeCertificate *  g_mime_certificate_new              ();
    GMimePubKeyAlgo     g_mime_certificate_get_pubkey_algo  (GMimeCertificate *cert);
    void                g_mime_certificate_set_pubkey_algo  (GMimeCertificate *cert, GMimePubKeyAlgo algo);
    GMimeDigestAlgo     g_mime_certificate_get_digest_algo  (GMimeCertificate *cert);
    void                g_mime_certificate_set_digest_algo  (GMimeCertificate *cert, GMimeDigestAlgo algo);
    const(ubyte*)         g_mime_certificate_get_issuer_serial (GMimeCertificate *cert);
    void                g_mime_certificate_set_issuer_serial (GMimeCertificate *cert, const(ubyte*) issuer_serial);
    const(ubyte*)         g_mime_certificate_get_issuer_name  (GMimeCertificate *cert);
    void                g_mime_certificate_set_issuer_name  (GMimeCertificate *cert, const(ubyte*) issuer_name);
    const(ubyte*)         g_mime_certificate_get_fingerprint  (GMimeCertificate *cert);
    void                g_mime_certificate_set_fingerprint  (GMimeCertificate *cert, const(ubyte*) fingerprint);
    time_t              g_mime_certificate_get_created      (GMimeCertificate *cert);
    void                g_mime_certificate_set_created      (GMimeCertificate *cert, time_t created);
    time_t              g_mime_certificate_get_expires      (GMimeCertificate *cert);
    void                g_mime_certificate_set_expires      (GMimeCertificate *cert, time_t expires);
    const(ubyte*)         g_mime_certificate_get_key_id       (GMimeCertificate *cert);
    void                g_mime_certificate_set_key_id       (GMimeCertificate *cert, const(ubyte*) key_id);
    GMimeCertificateTrust g_mime_certificate_get_trust      (GMimeCertificate *cert);
    void                g_mime_certificate_set_trust        (GMimeCertificate *cert, GMimeCertificateTrust trust);
    const(ubyte*)         g_mime_certificate_get_email        (GMimeCertificate *cert);
    void                g_mime_certificate_set_email        (GMimeCertificate *cert, const(ubyte*) email);
    const(ubyte*)         g_mime_certificate_get_name         (GMimeCertificate *cert);
    void                g_mime_certificate_set_name         (GMimeCertificate *cert, const(ubyte*) name);

    GMimeCertificateList * g_mime_certificate_list_new      ();
    int                 g_mime_certificate_list_length      (GMimeCertificateList *list);
    void                g_mime_certificate_list_clear       (GMimeCertificateList *list);
    int                 g_mime_certificate_list_add         (GMimeCertificateList *list, GMimeCertificate *cert);
    void                g_mime_certificate_list_insert      (GMimeCertificateList *list, int index, GMimeCertificate *cert);
    bint            g_mime_certificate_list_remove      (GMimeCertificateList *list, GMimeCertificate *cert);
    bint            g_mime_certificate_list_remove_at   (GMimeCertificateList *list, int index);
    bint            g_mime_certificate_list_contains    (GMimeCertificateList *list, GMimeCertificate *cert);
    int                 g_mime_certificate_list_index_of    (GMimeCertificateList *list, GMimeCertificate *cert);
    GMimeCertificate *  g_mime_certificate_list_get_certificate (GMimeCertificateList *list, int index);
    void                g_mime_certificate_list_set_certificate (GMimeCertificateList *list, int index, GMimeCertificate *cert);



    enum GMimeSignatureError
    {
        None = 0,
        ExpSig      = (1 << 0),  /* expired signature */
        NoPubKey   = (1 << 1),  /* no public key */
        ExpKeySig   = (1 << 2),  /* expired key */
        RevKeySig   = (1 << 3),  /* revoked key */
        UnsuppAlgo = (1 << 4)   /* unsupported algorithm */
    }

    struct GMimeSignature {};
    GMimeSignature *    g_mime_signature_new                ();
    GMimeCertificate *  g_mime_signature_get_certificate    (GMimeSignature *sig);
    void                g_mime_signature_set_certificate    (GMimeSignature *sig,
                                                             GMimeCertificate *cert);
    GMimeSignatureStatus g_mime_signature_get_status        (GMimeSignature *sig);
    void                g_mime_signature_set_status         (GMimeSignature *sig,
                                                             GMimeSignatureStatus status);
    GMimeSignatureError g_mime_signature_get_errors         (GMimeSignature *sig);
    void                g_mime_signature_set_errors         (GMimeSignature *sig,
                                                             GMimeSignatureError errors);
    time_t              g_mime_signature_get_created        (GMimeSignature *sig);
    void                g_mime_signature_set_created        (GMimeSignature *sig,
                                                             time_t created);
    time_t              g_mime_signature_get_expires        (GMimeSignature *sig);
    void                g_mime_signature_set_expires        (GMimeSignature *sig,
                                                             time_t expires);

    struct GMimeSignatureList {};
    GMimeSignatureList * g_mime_signature_list_new          ();
    int                 g_mime_signature_list_length        (GMimeSignatureList *list);
    void                g_mime_signature_list_clear         (GMimeSignatureList *list);
    int                 g_mime_signature_list_add           (GMimeSignatureList *list,
                                                             GMimeSignature *sig);
    void                g_mime_signature_list_insert        (GMimeSignatureList *list,
                                                             int index,
                                                             GMimeSignature *sig);
    bint            g_mime_signature_list_remove        (GMimeSignatureList *list,
                                                             GMimeSignature *sig);
    bint            g_mime_signature_list_remove_at     (GMimeSignatureList *list,
                                                             int index);
    bint            g_mime_signature_list_contains      (GMimeSignatureList *list,
                                                             GMimeSignature *sig);
    int                 g_mime_signature_list_index_of      (GMimeSignatureList *list,
                                                             GMimeSignature *sig);
    GMimeSignature *    g_mime_signature_list_get_signature (GMimeSignatureList *list,
                                                             int index);
    void                g_mime_signature_list_set_signature (GMimeSignatureList *list,
                                                             int index,
                                                             GMimeSignature *sig);

    alias GMimePasswordRequestFunc= bint function(GMimeCryptoContext *ctx, const(ubyte*) user_id, const(ubyte*) prompt_ctx,
                                                             bint reprompt, GMimeStream *response, GError **err);
    struct GMimeCryptoContext {};
    void                g_mime_crypto_context_set_request_password (GMimeCryptoContext *ctx, GMimePasswordRequestFunc request_passwd);
    const(ubyte*)         g_mime_crypto_context_get_signature_protocol (GMimeCryptoContext *ctx);
    const(ubyte*)         g_mime_crypto_context_get_encryption_protocol (GMimeCryptoContext *ctx);
    const(ubyte*)         g_mime_crypto_context_get_key_exchange_protocol (GMimeCryptoContext *ctx);
    GMimeDigestAlgo     g_mime_crypto_context_digest_id     (GMimeCryptoContext *ctx, const(ubyte*) name);
    const(ubyte*)         g_mime_crypto_context_digest_name   (GMimeCryptoContext *ctx, GMimeDigestAlgo digest);
    int                 g_mime_crypto_context_sign          (GMimeCryptoContext *ctx, const(ubyte*) userid, GMimeDigestAlgo digest,
        GMimeStream *istream, GMimeStream *ostream, GError **err);
    GMimeSignatureList * g_mime_crypto_context_verify       (GMimeCryptoContext *ctx, GMimeDigestAlgo digest, GMimeStream *istream, GMimeStream *sigstream,
        GError **err);
    int                 g_mime_crypto_context_encrypt       (GMimeCryptoContext *ctx, bint sign, const(ubyte*) userid, GMimeDigestAlgo digest,
                                                             GPtrArray *recipients, GMimeStream *istream, GMimeStream *ostream, GError **err);
    GMimeDecryptResult * g_mime_crypto_context_decrypt      (GMimeCryptoContext *ctx, GMimeStream *istream, GMimeStream *ostream, GError **err);
    int                 g_mime_crypto_context_import_keys   (GMimeCryptoContext *ctx, GMimeStream *istream, GError **err);
    int                 g_mime_crypto_context_export_keys   (GMimeCryptoContext *ctx, GPtrArray *keys, GMimeStream *ostream, GError **err);

    enum GMimeCipherAlgo
    {
        Default=0,
        Idea=1,
        TripleDES=2,
        Cast5       = 3,
        BlowFish    = 4,
        AES         = 7,
        AES192      = 8,
        AES256      = 9,
        TwoFish     = 10,
        Camellia128 = 11,
        Camellia192 = 12,
        Camellia256 = 13,
    }

    struct GMimeDecryptResult {};
    GMimeDecryptResult * g_mime_decrypt_result_new();
    GMimeCertificateList * g_mime_decrypt_result_get_recipients(GMimeDecryptResult *result);
    void g_mime_decrypt_result_set_recipients(GMimeDecryptResult *result, GMimeCertificateList *recipients);
    GMimeSignatureList * g_mime_decrypt_result_get_signatures(GMimeDecryptResult *result);
    void g_mime_decrypt_result_set_signatures(GMimeDecryptResult *result, GMimeSignatureList *signatures);
    GMimeCipherAlgo g_mime_decrypt_result_get_cipher(GMimeDecryptResult *result);
    void g_mime_decrypt_result_set_cipher(GMimeDecryptResult *result, GMimeCipherAlgo cipher);
    GMimeDigestAlgo g_mime_decrypt_result_get_mdc(GMimeDecryptResult *result);
    void g_mime_decrypt_result_set_mdc(GMimeDecryptResult *result, GMimeDigestAlgo mdc);
}
/**
extern
{
alias GMIME_TYPE_OBJECT=g_mime_object_get_type;
GType g_mime_object_get_type (void);
#define G_TYPE_CHECK_INSTANCE_CAST(instance, g_type, c_type)    (_G_TYPE_CIC ((instance), (g_type), c_type))

alias GMIME_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GMIME_TYPE_OBJECT, GMimeObject))
#define GMIME_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GMIME_TYPE_OBJECT, GMimeObjectClass))
#define GMIME_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GMIME_TYPE_OBJECT))
#define GMIME_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GMIME_TYPE_OBJECT))
#define GMIME_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GMIME_TYPE_OBJECT, GMimeObjectClass))

*/