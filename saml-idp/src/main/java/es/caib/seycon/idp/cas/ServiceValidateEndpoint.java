package es.caib.seycon.idp.cas;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;

public class ServiceValidateEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());

	private boolean addAttributes;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doPost(req, resp);
	}
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String ticket = req.getParameter("ticket");
		String service = req.getParameter("service");
		String format = req.getParameter("format");
		if ("JSON".equals(format)) {
			resp.setContentType("application/json");
		} else {
			resp.setContentType("text/xml");
		}
		resp.setCharacterEncoding("utf-8");
		final ServletOutputStream out = resp.getOutputStream();
		try {
			if (service == null) {
				failure(out, format, "INVALID_REQUEST", "Missing service attribute");
				resp.setStatus(HttpServletResponse.SC_OK);
			} else {
				TokenHandler h = TokenHandler.instance();
				TokenInfo t = null;
				t = h.getToken(ticket);
				if (t == null) {
					failure(out, format, "INVALID_REQUEST", "Wrong service name");
					resp.setStatus(HttpServletResponse.SC_OK);
				} else if (! service.equals(t.getRequest().getFederationMember().getPublicId())) {
					failure(out, format, "INVALID_SERVICE", "Wrong service name");
					resp.setStatus(HttpServletResponse.SC_OK);
				} else {
					Map<String, Object> atts = new UserAttributesGenerator().generateAttributes(req.getServletContext(), t, false, false, true);

					success (out, format, t, atts);
					resp.setStatus(HttpServletResponse.SC_OK);
				}
			}
		} catch (Exception e) {
			log.warn("Error checking for CAS ticket", e);
			try {
				failure(out, format, "INTERNAL_ERROR", "Error processing request. See log file");
			} catch (Exception e1) {
				throw new ServletException(e);
			}
			resp.setStatus(HttpServletResponse.SC_OK);
		}
	}

	private void failure(ServletOutputStream out, String format, String code, String description) throws TransformerConfigurationException, TransformerException, TransformerFactoryConfigurationError, IOException, ParserConfigurationException {
		if ("JSON".equalsIgnoreCase(format)) {
			JSONObject o3 = new JSONObject();
			o3.put("code",  code);
			o3.put("description", description);
			JSONObject o2 = new JSONObject();
			o2.put("authenticationFailure", o3);
			JSONObject o = new JSONObject();
			o.put("serviceResponse", o2);
			out.println(o.toString());
		} else {
			Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			Element o3 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:authenticationFailure");
			o3.setAttribute("code", code);
			o3.setTextContent(description);

			Element o2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:serviceResponse");
			o2.appendChild(o3);
			
			doc.appendChild(o2);
			
			TransformerFactory.newInstance()
				.newTransformer()
				.transform(new DOMSource(doc), new StreamResult(out));
		}
		
	}
	
	private void success(ServletOutputStream out, String format, TokenInfo t, Map<String, Object> atts) throws TransformerConfigurationException, TransformerException, TransformerFactoryConfigurationError, IOException, ParserConfigurationException {
		String user = (String) atts.get("uid");
		
		SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-YYYY'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String authenticationDate = sdf.format(t.getCreated());
		
		if ("JSON".equalsIgnoreCase(format)) {
			JSONObject o3 = new JSONObject();
			o3.put("user",  user);
			JSONObject o2 = new JSONObject();
			o2.put("authenticationSucces", o3);
			if (addAttributes) {
				JSONObject atts2 = new JSONObject();
				for ( Entry<String, Object> entry: atts.entrySet()) {
					String v = stringify ( entry.getValue() );
					if (v != null) 
						atts2.put(entry.getKey(), v);
				}
				atts2.put("authenticationDate", authenticationDate);
				atts2.put("longTermAuthenticationRequestTokenUsed", false);
				atts2.put("isFromNewLogin", true);
				o2.put("attributes", atts2);
			}
			JSONObject o = new JSONObject();
			o.put("serviceResponse", o2);
			out.println(o.toString());
		} else {
			Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			Element o4 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:user");
			o4.setTextContent(user);

			Element o3 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:authenticationSuccess");
			o3.appendChild(o4);
			
			if (addAttributes) {
				Element atts2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:attributes");
				o3.appendChild(atts2);
				for ( Entry<String, Object> entry: atts.entrySet()) {
					String v = stringify ( entry.getValue() );
					if (v != null) {
						try {
							String key = entry.getKey().replace("&", "")
									.replace("<", "")
									.replace(">", "")
									.replace(" ", "");
							Element att = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:"+key);
							att.setTextContent(v);
							atts2.appendChild(att);
						} catch (Exception e) {
							// Cannot serialize
						}
					}
				}
				Element att2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:authenticationDate");
				att2.setTextContent(authenticationDate);
				atts2.appendChild(att2);

				att2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:langTermAuthenticationRequestTokenUsed");
				att2.setTextContent("false");
				atts2.appendChild(att2);

				att2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:isFromNewLogin");
				att2.setTextContent("true");
				atts2.appendChild(att2);
			}

			Element o2 = doc.createElementNS("http://www.yale.edu/tp/cas", "cas:serviceResponse");
			o2.appendChild(o3);
			
			doc.appendChild(o2);
			
			TransformerFactory.newInstance()
				.newTransformer()
				.transform(new DOMSource(doc), new StreamResult(out));
		}
		
	}

	private String stringify(Object value) {
		if (value == null) return null;
		if (value instanceof Collection) {
			StringBuffer sb = new StringBuffer();
			for (Object v: (Collection) value) {
				if (v != null) {
					if (sb.length() > 0) sb.append(", ");
					sb.append(v.toString());
				}
			}
		}
		return value.toString();
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		addAttributes = "3".equals(config.getInitParameter("version"));
	}

}