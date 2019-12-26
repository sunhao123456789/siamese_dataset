static int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                         unsigned int len, int create_empty_fragment)
{
    unsigned char *p, *plen;
    int i, mac_size, clear = 0;
    int prefix_len = 0;
    int eivlen;
    long align = 0;
    SSL3_RECORD *wr;
    SSL3_BUFFER *wb = &(s->s3->wbuf);
    SSL_SESSION *sess;

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (wb->left != 0)
        return (ssl3_write_pending(s, type, buf, len));

    /* If we have an alert to send, lets send it */
    if (s->s3->alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return (i);
        /* if it went, fall through and send more stuff */
    }

    if (wb->buf == NULL)
        if (!ssl3_setup_write_buffer(s))
            return -1;

    if (len == 0 && !create_empty_fragment)
        return 0;

    wr = &(s->s3->wrec);
    sess = s->session;

    if ((sess == NULL) ||
        (s->enc_write_ctx == NULL) ||
        (EVP_MD_CTX_md(s->write_hash) == NULL)) {
#if 1
        clear = s->enc_write_ctx ? 0 : 1; /* must be AEAD cipher */
#else
        clear = 1;
#endif
        mac_size = 0;
    } else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            goto err;
    }

    /*
     * 'create_empty_fragment' is true only when this function calls itself
     */
    if (!clear && !create_empty_fragment && !s->s3->empty_fragment_done) {
        /*
         * countermeasure against known-IV weakness in CBC ciphersuites (see
         * http://www.openssl.org/~bodo/tls-cbc.txt)
         */

        if (s->s3->need_empty_fragments && type == SSL3_RT_APPLICATION_DATA) {
            /*
             * recursive function call with 'create_empty_fragment' set; this
             * prepares and buffers the data for an empty fragment (these
             * 'prefix_len' bytes are sent out later together with the actual
             * payload)
             */
            prefix_len = do_ssl3_write(s, type, buf, 0, 1);
            if (prefix_len <= 0)
                goto err;

            if (prefix_len >
                (SSL3_RT_HEADER_LENGTH + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD))
            {
                /* insufficient space */
                SSLerr(SSL_F_DO_SSL3_WRITE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        s->s3->empty_fragment_done = 1;
    }

    if (create_empty_fragment) {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        /*
         * extra fragment would be couple of cipher blocks, which would be
         * multiple of SSL3_ALIGN_PAYLOAD, so if we want to align the real
         * payload, then we can just pretent we simply have two headers.
         */
        align = (long)wb->buf + 2 * SSL3_RT_HEADER_LENGTH;
        align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = wb->buf + align;
        wb->offset = align;
    } else if (prefix_len) {
        p = wb->buf + wb->offset + prefix_len;
    } else {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        align = (long)wb->buf + SSL3_RT_HEADER_LENGTH;
        align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = wb->buf + align;
        wb->offset = align;
    }

    /* write the header */

    *(p++) = type & 0xff;
    wr->type = type;

    *(p++) = (s->version >> 8);
    /*
     * Some servers hang if iniatial client hello is larger than 256 bytes
     * and record version number > TLS 1.0
     */
    if (s->state == SSL3_ST_CW_CLNT_HELLO_B
        && !s->renegotiate && TLS1_get_version(s) > TLS1_VERSION)
        *(p++) = 0x1;
    else
        *(p++) = s->version & 0xff;

    /* field where we are to write out packet length */
    plen = p;
    p += 2;
    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->enc_write_ctx && SSL_USE_EXPLICIT_IV(s)) {
        int mode = EVP_CIPHER_CTX_mode(s->enc_write_ctx);
        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_iv_length(s->enc_write_ctx);
            if (eivlen <= 1)
                eivlen = 0;
        }
        /* Need explicit part of IV for GCM mode */
        else if (mode == EVP_CIPH_GCM_MODE)
            eivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        else
            eivlen = 0;
    } else
        eivlen = 0;

    /* lets setup the record stuff. */
    wr->data = p + eivlen;
    wr->length = (int)len;
    wr->input = (unsigned char *)buf;

    /*
     * we now 'read' from wr->input, wr->length bytes into wr->data
     */

    /* first we compress */
    if (s->compress != NULL) {
        if (!ssl3_do_compress(s)) {
            SSLerr(SSL_F_DO_SSL3_WRITE, SSL_R_COMPRESSION_FAILURE);
            goto err;
        }
    } else {
        memcpy(wr->data, wr->input, wr->length);
        wr->input = wr->data;
    }

    /*
     * we should still have the output to wr->data and the input from
     * wr->input.  Length should be wr->length. wr->data still points in the
     * wb->buf
     */

    if (mac_size != 0) {
        if (s->method->ssl3_enc->mac(s, &(p[wr->length + eivlen]), 1) < 0)
            goto err;
        wr->length += mac_size;
    }

    wr->input = p;
    wr->data = p;

    if (eivlen) {
        /*
         * if (RAND_pseudo_bytes(p, eivlen) <= 0) goto err;
         */
        wr->length += eivlen;
    }

    if (s->method->ssl3_enc->enc(s, 1) < 1)
        goto err;

    /* record length after mac and block padding */
    s2n(wr->length, plen);

    if (s->msg_callback)
        s->msg_callback(1, 0, SSL3_RT_HEADER, plen - 5, 5, s,
                        s->msg_callback_arg);

    /*
     * we should now have wr->data pointing to the encrypted data, which is
     * wr->length long
     */
    wr->type = type;            /* not needed but helps for debugging */
    wr->length += SSL3_RT_HEADER_LENGTH;

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        return wr->length;
    }

    /* now let's set up wb */
    wb->left = prefix_len + wr->length;

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    s->s3->wpend_tot = len;
    s->s3->wpend_buf = buf;
    s->s3->wpend_type = type;
    s->s3->wpend_ret = len;

    /* we now just need to write the buffer */
    return ssl3_write_pending(s, type, buf, len);
 err:
    return -1;
}
