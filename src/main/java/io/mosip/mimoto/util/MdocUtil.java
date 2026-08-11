package io.mosip.mimoto.util;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import io.mosip.mimoto.constant.CredentialFormat;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.List;

@Slf4j
public final class MdocUtil {

    private MdocUtil() {}

    public static Object wrapIssuerSignedIfNeeded(Object credential, String format, String doctype) {
        if (!CredentialFormat.MSO_MDOC.getFormat().equalsIgnoreCase(format)) return credential;
        if (!(credential instanceof String issuerSignedB64) || issuerSignedB64.isBlank()) return credential;
        if (doctype == null || doctype.isBlank()) {
            log.warn("MdocUtil: mso_mdoc credential has no doctype from wellknown; skipping wrap");
            return credential;
        }
        try {
            byte[] issuerSignedBytes = Base64.getUrlDecoder().decode(issuerSignedB64);
            if (isAlreadyMobileDocument(issuerSignedBytes)) return credential;
            String wrapped = buildMobileDocument(issuerSignedBytes, doctype);
            log.info("MdocUtil: wrapped IssuerSigned into MobileDocument for doctype={}", doctype);
            return wrapped;
        } catch (Exception e) {
            log.warn("MdocUtil: failed to wrap IssuerSigned as MobileDocument: {}; using as-is", e.getMessage());
            return credential;
        }
    }

    private static boolean isAlreadyMobileDocument(byte[] bytes) {
        try {
            List<DataItem> items = CborDecoder.decode(bytes);
            if (items.isEmpty() || !(items.get(0) instanceof co.nstant.in.cbor.model.Map map)) return false;
            DataItem docTypeValue = map.get(new UnicodeString("docType"));
            return docTypeValue instanceof UnicodeString;
        } catch (Exception e) {
            return false;
        }
    }

    private static String buildMobileDocument(byte[] issuerSignedBytes, String doctype) throws Exception {
        List<DataItem> items = CborDecoder.decode(issuerSignedBytes);
        DataItem issuerSigned = items.get(0);

        co.nstant.in.cbor.model.Map mobileDocument = new co.nstant.in.cbor.model.Map();
        mobileDocument.put(new UnicodeString("docType"), new UnicodeString(doctype));
        mobileDocument.put(new UnicodeString("issuerSigned"), issuerSigned);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(mobileDocument);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }
}