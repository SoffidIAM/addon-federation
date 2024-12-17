package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.passrecover.PassrecoverServiceLocator;
import com.soffid.iam.addons.passrecover.common.MissconfiguredRecoverException;
import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.addons.passrecover.common.UserAnswer;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserService;

import es.caib.seycon.ng.ServiceLocator;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.BadPasswordException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.servei.InternalPasswordService;

public class RecoverPasswordServlet extends HttpServlet {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost (req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
	    String action = req.getParameter("action");
	    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
	            "UTF-8"));
	    try {
	        if ("requestChallenge".equals(action))
	            writer.write(doRequestChallengeAction(req, resp));
	        else if ("responseChallenge".equals(action))
	            writer.write(doResponseChallengeAction(req, resp));
	        else if ("resetPassword".equals(action))
	            writer.write(resetPassword(req, resp));
	        else
	            throw new Exception("Invalid action " + action);
	    } catch (Exception e) {
	        log.warn("Error recovering password", e);
	        writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
	    }
	    writer.close();
	}

	private String doRequestChallengeAction(HttpServletRequest req,
			HttpServletResponse resp) throws InternalErrorException, UnsupportedEncodingException, UnknownUserException, MissconfiguredRecoverException {
		RecoverPasswordUserService svc = PassrecoverServiceLocator.instance().getRecoverPasswordUserService();
		String user = req.getParameter("user");
		String dispatcher = req.getParameter("domain");
		if (dispatcher == null  || dispatcher.length() == 0)
		{
			InternalPasswordService ips = ServiceLocator.instance().getInternalPasswordService();
			dispatcher = ips.getDefaultDispatcher();
		}
		
		RecoverPasswordChallenge request = svc.requestChallenge(user, dispatcher);
		StringBuffer b = new StringBuffer ( "OK|" );
		b.append (request.getChallengId());
		for ( UserAnswer question: request.getQuestions())
		{
			b.append ("|").append( URLEncoder.encode(question.getQuestion(), "UTF-8"));
		}
		return b.toString();
	}
	
	
	private String doResponseChallengeAction(HttpServletRequest req,
			HttpServletResponse resp) throws InternalErrorException, UnsupportedEncodingException {
		
		log.info("Received response challenge from "+req.getParameter("user"));

		RecoverPasswordUserService svc = PassrecoverServiceLocator.instance().getRecoverPasswordUserService();
		
		
		RecoverPasswordChallenge request = new RecoverPasswordChallenge();
		request.setUser( req.getParameter("user") );
		String dispatcher = req.getParameter("domain");
		if (dispatcher == null  || dispatcher.length() == 0)
		{
			InternalPasswordService ips = ServiceLocator.instance().getInternalPasswordService();
			dispatcher = ips.getDefaultDispatcher();
		}
		request.setDispatcher( dispatcher );
		request.setChallengId( Long.decode(req.getParameter("id")) );
		request.setChallengeDate(Calendar.getInstance());
		request.setExpirationDate(Calendar.getInstance());
		List<UserAnswer> q = new LinkedList<UserAnswer>();
		
		for (String param: (Set<String>) req.getParameterMap().keySet())
		{
			if (!"user".equals(param) && !param.startsWith("domain") &&
					!"id".equals(param) && !"action".equals(param)) {
				UserAnswer a = new UserAnswer();
				a.setQuestion(param);
				a.setAnswer(req.getParameter(param));
				q.add(a);
			}
		}

		request.setQuestions(q);
		
		if (svc.responseChallenge(request))
		{
			return "OK";
		} else {
			return "FAILED";
		}
	}
	
	private String resetPassword(HttpServletRequest req,
			HttpServletResponse resp) throws InternalErrorException, UnsupportedEncodingException {
		RecoverPasswordUserService svc = PassrecoverServiceLocator.instance().getRecoverPasswordUserService();
		
		
		RecoverPasswordChallenge request = new RecoverPasswordChallenge();
		request.setUser( req.getParameter("user") );
		String dispatcher = req.getParameter("domain");
		if (dispatcher == null  || dispatcher.length() == 0)
		{
			InternalPasswordService ips = ServiceLocator.instance().getInternalPasswordService();
			dispatcher = ips.getDefaultDispatcher();
		}
		request.setDispatcher( dispatcher );
		request.setChallengId( Long.decode(req.getParameter("id")) );
		request.setPassword(new Password(req.getParameter ("password")));
		request.setQuestions(new LinkedList<UserAnswer>());
		request.getQuestions().add(new UserAnswer());
		request.setChallengeDate(Calendar.getInstance());
		request.setExpirationDate(Calendar.getInstance());

		try 
		{
			svc.resetPassword(request);
			return "OK";
			
		} catch (BadPasswordException e)
		{
			return "BADPASSWORD|"+e.getMessage();
		}
	}
}
