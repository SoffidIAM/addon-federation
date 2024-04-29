package es.caib.seycon.idp.ui;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.config.Config;
import com.soffid.iam.utils.Security;

public class LogFilter implements Filter {
	static PrintStream out = null;
	static String day;
	private FilterConfig filterConfig;
	SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
	SimpleDateFormat dateFormat2 = new SimpleDateFormat("HH:mm:ss");

	public void init(FilterConfig filterConfig) throws ServletException {
		openLog();
		this.filterConfig = filterConfig;
	}

	public void openLog() throws ServletException {
		String today = dateFormat.format(new Date());
		if (out == null || ! today.equals(day))
		{
			File dir;
			try {
				String t = "access-"+today+".log";
				dir = new File(Config.getConfig().getLogDir(), t);
				day = today;
				if (out != null)
					out.close();
				out = new PrintStream( new FileOutputStream(dir, true) );
			} catch (IOException e) {
				throw new ServletException(e);
			}
		}
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponseWrapper resp = new HttpServletResponseWrapper((HttpServletResponse) response);
		if (! "GET".equals(req.getMethod()) && ! "POST".equals(req.getMethod())  && ! "OPTIONS".equals(req.getMethod())
				&& (req.getContextPath().contains("/sse/") || req.getContextPath().contains("/ssf/")))
		{
			resp.sendError(HttpServletResponse.SC_FORBIDDEN);
		} else {
			String path = req.getContextPath()+req.getServletPath()+
					(req.getPathInfo() == null ? "" : req.getPathInfo());
			if (req.getQueryString() != null) path += "?"+req.getQueryString();
			try {
				chain.doFilter(request, response);
				openLog();
				out.println (dateFormat2.format(new Date())+" "+request.getRemoteAddr()+" "+resp.error+" "+ path );
			} catch (Exception e) {
				out.println (dateFormat2.format(new Date())+" "+request.getRemoteAddr()+" "+e.toString()+" "+ path );
				if (e instanceof IOException)
					throw e;
				else
					throw new ServletException(e);
			}
			out.flush();
		}
	}

	public void destroy() {
	}

}

class HttpServletResponseWrapper implements HttpServletResponse {
	HttpServletResponse target;
	int error;

	public HttpServletResponseWrapper(HttpServletResponse target) {
		super();
		error = 200;
		this.target = target;
	}

	public void addCookie(Cookie cookie) {
		target.addCookie(cookie);
	}

	public boolean containsHeader(String name) {
		return target.containsHeader(name);
	}

	public String encodeURL(String url) {
		return target.encodeURL(url);
	}

	public String getCharacterEncoding() {
		return target.getCharacterEncoding();
	}

	public String encodeRedirectURL(String url) {
		return target.encodeRedirectURL(url);
	}

	public String getContentType() {
		return target.getContentType();
	}

	public String encodeUrl(String url) {
		return target.encodeUrl(url);
	}

	public String encodeRedirectUrl(String url) {
		return target.encodeRedirectUrl(url);
	}

	public ServletOutputStream getOutputStream() throws IOException {
		return target.getOutputStream();
	}

	public void sendError(int sc, String msg) throws IOException {
		error = sc;
		target.sendError(sc, msg);
	}

	public PrintWriter getWriter() throws IOException {
		return target.getWriter();
	}

	public void sendError(int sc) throws IOException {
		error = sc;
		target.sendError(sc);
	}

	public void sendRedirect(String location) throws IOException {
		error = HttpServletResponse.SC_MOVED_TEMPORARILY;
		target.sendRedirect(location);
	}

	public void setCharacterEncoding(String charset) {
		target.setCharacterEncoding(charset);
	}

	public void setDateHeader(String name, long date) {
		target.setDateHeader(name, date);
	}

	public void addDateHeader(String name, long date) {
		target.addDateHeader(name, date);
	}

	public void setContentLength(int len) {
		target.setContentLength(len);
	}

	public void setHeader(String name, String value) {
		target.setHeader(name, value);
	}

	public void setContentType(String type) {
		target.setContentType(type);
	}

	public void addHeader(String name, String value) {
		target.addHeader(name, value);
	}

	public void setIntHeader(String name, int value) {
		target.setIntHeader(name, value);
	}

	public void setBufferSize(int size) {
		target.setBufferSize(size);
	}

	public void addIntHeader(String name, int value) {
		target.addIntHeader(name, value);
	}

	public void setStatus(int sc) {
		target.setStatus(sc);
	}

	public void setStatus(int sc, String sm) {
		target.setStatus(sc, sm);
	}

	public int getBufferSize() {
		return target.getBufferSize();
	}

	public void flushBuffer() throws IOException {
		target.flushBuffer();
	}

	public void resetBuffer() {
		target.resetBuffer();
	}

	public boolean isCommitted() {
		return target.isCommitted();
	}

	public void reset() {
		target.reset();
	}

	public void setLocale(Locale loc) {
		target.setLocale(loc);
	}

	public Locale getLocale() {
		return target.getLocale();
	}

	public int getError() {
		return error;
	}

	public void setError(int error) {
		this.error = error;
	}

	public void setContentLengthLong(long length) {
		target.setContentLengthLong(length);
	}

	public int getStatus() {
		return target.getStatus();
	}

	public String getHeader(String name) {
		return target.getHeader(name);
	}

	public Collection<String> getHeaders(String name) {
		return target.getHeaders(name);
	}

	public Collection<String> getHeaderNames() {
		return target.getHeaderNames();
	}
	
}
