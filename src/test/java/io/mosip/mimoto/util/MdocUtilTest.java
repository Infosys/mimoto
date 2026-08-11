package io.mosip.mimoto.util;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.UnicodeString;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class MdocUtilTest {

    private static final String MSO_MDOC = "mso_mdoc";
    private static final String DOCTYPE = "org.iso.18013.5.1.mDL";

    private static String buildIssuerSignedB64() throws Exception {
        co.nstant.in.cbor.model.Map issuerSigned = new co.nstant.in.cbor.model.Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), new co.nstant.in.cbor.model.Map());
        issuerSigned.put(new UnicodeString("issuerAuth"), new Array());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(issuerSigned);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    private static String buildMobileDocumentB64() throws Exception {
        co.nstant.in.cbor.model.Map issuerSigned = new co.nstant.in.cbor.model.Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), new co.nstant.in.cbor.model.Map());

        co.nstant.in.cbor.model.Map mobileDocument = new co.nstant.in.cbor.model.Map();
        mobileDocument.put(new UnicodeString("docType"), new UnicodeString(DOCTYPE));
        mobileDocument.put(new UnicodeString("issuerSigned"), issuerSigned);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(mobileDocument);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    @Test
    void wrapIssuerSignedIfNeeded_nonMdocFormat_returnsCredentialUnchanged() throws Exception {
        String credential = buildIssuerSignedB64();
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(credential, "jwt_vc", DOCTYPE);
        assertSame(credential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_credentialIsNotString_returnsCredentialUnchanged() {
        Object credential = java.util.Map.of("key", "value");
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(credential, MSO_MDOC, DOCTYPE);
        assertSame(credential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_blankCredentialString_returnsCredentialUnchanged() {
        String credential = "   ";
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(credential, MSO_MDOC, DOCTYPE);
        assertSame(credential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_nullDoctype_returnsCredentialUnchanged() throws Exception {
        String credential = buildIssuerSignedB64();
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(credential, MSO_MDOC, null);
        assertSame(credential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_blankDoctype_returnsCredentialUnchanged() throws Exception {
        String credential = buildIssuerSignedB64();
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(credential, MSO_MDOC, "  ");
        assertSame(credential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_alreadyMobileDocument_returnsCredentialUnchanged() throws Exception {
        String mobileDocument = buildMobileDocumentB64();
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(mobileDocument, MSO_MDOC, DOCTYPE);
        assertSame(mobileDocument, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_validIssuerSigned_returnsWrappedMobileDocumentWithDocType() throws Exception {
        String issuerSigned = buildIssuerSignedB64();
        String result = (String) MdocUtil.wrapIssuerSignedIfNeeded(issuerSigned, MSO_MDOC, DOCTYPE);

        assertNotNull(result);
        assertNotEquals(issuerSigned, result);

        byte[] decoded = Base64.getUrlDecoder().decode(result);
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) CborDecoder.decode(decoded).get(0);
        assertEquals(DOCTYPE, map.get(new UnicodeString("docType")).toString());
        assertNotNull(map.get(new UnicodeString("issuerSigned")));
    }

    @Test
    void wrapIssuerSignedIfNeeded_invalidBase64_returnsCredentialUnchanged() {
        String badCredential = "!!!not-valid-base64!!!";
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(badCredential, MSO_MDOC, DOCTYPE);
        assertSame(badCredential, result);
    }

    @Test
    void wrapIssuerSignedIfNeeded_emptyBytesAfterDecode_returnsCredentialUnchanged() {
        // Base64url of empty byte array → CborDecoder returns empty list → items.get(0) throws IOOBE
        String emptyBytes = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[0]);
        Object result = MdocUtil.wrapIssuerSignedIfNeeded(emptyBytes, MSO_MDOC, DOCTYPE);
        assertSame(emptyBytes, result);
    }
}
