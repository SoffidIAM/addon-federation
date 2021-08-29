package es.caib.seycon.idp.impersonation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class ImpersonateResponse implements HttpServletResponse {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	
	private String characterEncoding;
	private String contentType;

	private int contentLength;

	private long contentLengthLong;

	private int bufferSize;

	private Locale locale;

	List<Cookie> cookies = new LinkedList<>(); 
	List<String[]> headers = new LinkedList<>();

	private int status;

	@Override
	public String getCharacterEncoding() {
		return characterEncoding;
	}

	@Override
	public String getContentType() {
		return contentType;
	}

	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		return new ServletOutputStream() {
			@Override
			public void write(int b) throws IOException {
				out.write(b);
			}
			
			@Override
			public void setWriteListener(WriteListener listener) {
			}
			
			@Override
			public boolean isReady() {
				return true;
			}
		} ;
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		return new PrintWriter(out);
	}

	@Override
	public void setCharacterEncoding(String charset) {
		this.characterEncoding = charset;
	}

	@Override
	public void setContentLength(int len) {
		this.contentLength = len;
	}

	@Override
	public void setContentLengthLong(long length) {
		this.contentLengthLong = length;

	}

	@Override
	public void setContentType(String type) {
		this.contentType = type;
	}

	@Override
	public void setBufferSize(int size) {
		this.bufferSize = size;
	}

	@Override
	public int getBufferSize() {
		return bufferSize;
	}

	@Override
	public void flushBuffer() throws IOException {
	}

	@Override
	public void resetBuffer() {
		out.reset();
	}

	@Override
	public boolean isCommitted() {
		return false;
	}

	@Override
	public void reset() {
		out.reset();
	}

	@Override
	public void setLocale(Locale loc) {
		this.locale = loc;
	}

	@Override
	public Locale getLocale() {
		return locale;
	}

	@Override
	public void addCookie(Cookie cookie) {
		cookies.add(cookie);
	}

	@Override
	public boolean containsHeader(String name) {
		for (String s[]: headers) {
			if (s[0].equals(name)) return true;
		}
		return false;
	}

	@Override
	public String encodeURL(String url) {
		return url;
	}

	@Override
	public String encodeRedirectURL(String url) {
		return url;
	}

	@Override
	public String encodeUrl(String url) {
		return url;
	}

	@Override
	public String encodeRedirectUrl(String url) {
		return url;
	}

	@Override
	public void sendError(int sc, String msg) throws IOException {
		setStatus(sc);
	}

	@Override
	public void sendError(int sc) throws IOException {
		setStatus(sc);
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
		setHeader("Location", location);
	}

	@Override
	public void setDateHeader(String name, long date) {
		deleteHeader(name);
		headers.add(new String[] {name, Long.toString(date)});
	}

	@Override
	public void addDateHeader(String name, long date) {
		headers.add(new String[] {name, Long.toString(date)});
		
	}

	@Override
	public void setHeader(String name, String value) {
		deleteHeader(name);
		headers.add(new String[] {name, value});
	}

	private void deleteHeader(String name) {
		for (Iterator<String[]> it = headers.iterator(); it.hasNext();) {
			String[] v = it.next();
			if (v[0].equals(name)) it.remove();
		}
	}

	@Override
	public void addHeader(String name, String value) {
		headers.add(new String[] {name, value});
	}

	@Override
	public void setIntHeader(String name, int value) {
		deleteHeader(name);
		headers.add(new String[] {name, Integer.toString(value)});
	}

	@Override
	public void addIntHeader(String name, int value) {
		headers.add(new String[] {name, Integer.toString(value)});
	}

	@Override
	public void setStatus(int sc) {
		status = sc;
	}

	@Override
	public void setStatus(int sc, String sm) {
		status = sc;
	}

	@Override
	public int getStatus() {
		return status;
	}

	@Override
	public String getHeader(String name) {
		for (Iterator<String[]> it = headers.iterator(); it.hasNext();) {
			String[] v = it.next();
			if (v[0].equals(name)) return v[1];
		}
		return null;
	}

	@Override
	public Collection<String> getHeaders(String name) {
		LinkedList<String> l = new LinkedList<String>();
		for (Iterator<String[]> it = headers.iterator(); it.hasNext();) {
			String[] v = it.next();
			if (v[0].equals(name)) l.add(v[1]);
		}
		return l;
	}

	@Override
	public Collection<String> getHeaderNames() {
		HashSet<String> l = new HashSet<String>();
		for (Iterator<String[]> it = headers.iterator(); it.hasNext();) {
			String[] v = it.next();
			l.add(v[0]);
		}
		return l;
	}

	public ByteArrayOutputStream getOut() {
		return out;
	}

	public int getContentLength() {
		return contentLength;
	}

	public long getContentLengthLong() {
		return contentLengthLong;
	}

	public List<Cookie> getCookies() {
		return cookies;
	}

	public List<String[]> getHeaders() {
		return headers;
	}

}
