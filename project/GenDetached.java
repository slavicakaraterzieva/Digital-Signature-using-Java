import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import org.w3c.dom.Document;
//import org.w3c.dom.Element;

public class GenDetached {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Please provide the XML file name as a terminal argument.");
            return;
        }

        // Get file name from the terminal argument
        String fileName = args[0];

        // Load existing XML file
        File xmlFile = new File(fileName);  
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);  // must be set
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xmlFile);

        // Create new content and add it to the document
        //Element newElement = doc.createElement("NewElement");
        //newElement.setTextContent("This is new content.");
        //doc.getDocumentElement().appendChild(newElement);

        // Prepare for signing the updated document
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null));
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null),
                Collections.singletonList(ref));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        XMLSignature signature = fac.newXMLSignature(si, ki);
        DOMSignContext signContext = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());  // Ensuring the correct node
        signature.sign(signContext);

        // Output the resulting document
        OutputStream os;
        os = new FileOutputStream(fileName);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }
}

