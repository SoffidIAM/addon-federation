package com.soffid.iam.addons.federation.interceptor;

import java.lang.reflect.InvocationTargetException;
import java.util.Date;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.beanutils.PropertyUtils;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntityDao;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.model.AccountEntityDao;
import com.soffid.iam.service.DispatcherService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SignalServiceInterceptor implements MethodInterceptor{
	SharedSignalEventsService sharedSignalEventsService;
	SseReceiverEntityDao  sseReceiverEntityDao;

	public SharedSignalEventsService getSharedSignalEventsService() {
		return sharedSignalEventsService;
	}

	public void setSharedSignalEventsService(SharedSignalEventsService sharedSignalEventsService) {
		this.sharedSignalEventsService = sharedSignalEventsService;
	}

	@Override
	public Object invoke(MethodInvocation m) throws Throwable {
		Object r = m.proceed();
		if (m.getMethod().getName().equals("signalAccount")) {
			signalAccount(m.getArguments());
		}
		if (m.getMethod().getName().equals("signalUser")) {
			signalUser(m.getArguments());
		}
		return r;
	}

	private void signalUser(Object[] arguments) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, InternalErrorException {
		String signal = (String) arguments[0];
		String user = (String) arguments[1];
		for (SseReceiverEntity receiver: getSseReceiverEntityDao().findByEventType(signal)) {
			SseEvent ev = new SseEvent();
			ev.setType(signal);
			ev.setUser(user);
			ev.setReceiver(receiver.getName());
			ev.setDate(new Date());
			populateEvent(ev, (String[])arguments[2]);
			getSharedSignalEventsService().addEvent(ev);
			break;
		}
	}

	private void populateEvent(SseEvent ev, String[] arguments) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException {
		for (int n = 0; n < arguments.length - 1; n += 2)
			PropertyUtils.setProperty(ev, (String) arguments[n], arguments[n+1]);
	}

	private void signalAccount(Object[] arguments) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, InternalErrorException {
		String signal = (String) arguments[0];
		String account = (String) arguments[1];
		String system = (String) arguments[2];
		for (SseReceiverEntity receiver: getSseReceiverEntityDao().findByEventType(signal)) {
			SseEvent ev = new SseEvent();
			ev.setType(signal);
			ev.setAccountName(account);
			ev.setAccountSystem(system);
			ev.setReceiver(receiver.getName());
			ev.setDate(new Date());
			populateEvent(ev, (String[])arguments[3]);
			getSharedSignalEventsService().addEvent(ev);
			break;
		}
	}

	public SseReceiverEntityDao getSseReceiverEntityDao() {
		return sseReceiverEntityDao;
	}

	public void setSseReceiverEntityDao(SseReceiverEntityDao sseReceiverEntityDao) {
		this.sseReceiverEntityDao = sseReceiverEntityDao;
	}
}
