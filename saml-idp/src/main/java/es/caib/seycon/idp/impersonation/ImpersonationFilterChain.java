package es.caib.seycon.idp.impersonation;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class ImpersonationFilterChain implements FilterChain {
	RequestDispatcher dispatcher;
	LinkedList<Filter> filters = new LinkedList<Filter>();
	@Override
	public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
		if (filters.isEmpty())
			dispatcher.include(request, response);
		else {
			Filter filter = filters.pop();
			filter.doFilter(request, response, this);
		}
	}
	public ImpersonationFilterChain(RequestDispatcher dispatcher) {
		super();
		this.dispatcher = dispatcher;
	}
	
	public void addFilter(Filter f) {
		filters.add(f);
	}

}
