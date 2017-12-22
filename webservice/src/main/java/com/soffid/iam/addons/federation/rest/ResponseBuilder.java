package com.soffid.iam.addons.federation.rest;

import java.net.URI;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class ResponseBuilder {

	/**
	 * In the case the only the HTTP code status is required
	 */
	public static Response responseOnlyHTTP(Status status) {
		return Response.status(status).build();
	}

	/**
	 * Generic error or unmanaged exception
	 */
	public static Response errorGeneric(Exception e) {
		return Response.serverError().entity(new ResponseError(getOriginalMessage(e))).build();
	}

	/**
	 * Custom error
	 */
	public static Response errorCustom(Status status, Exception e) {
		return Response.status(status).entity(new ResponseError(getOriginalMessage(e))).build();
	}

	/**
	 * Custom error
	 */
	public static Response errorCustom(Status status, String keyMessage, Object... args) {
		return Response.status(status).entity(new ResponseError(String.format(Messages.getString(keyMessage), args))).build();
	}

	/**
	 * Normal response with HTTP 200 and the JSON with data
	 */
	public static Response responseOk(Object obj) {
		return Response.ok().entity(obj).build();
	}

	/**
	 * Normal response with HTTP 200 and URI and the JSON with data
	 */
	public static Response responseOk(Object obj, URI uri) {
		return Response.created(uri).entity(obj).build();
	}

	/**
	 * Object list response
	 */
	public static Response responseList(Object obj) {
		return Response.ok().entity(obj).build();
	}

	/**
	 * Search and return the original message of the list of exceptions
	 */
	private static String getOriginalMessage(Exception e) {
		if (e == null) return "";
		String message = null;
		Throwable throwable = e.getCause();
		while (throwable != null) {
			message = throwable.getMessage();
			throwable = throwable.getCause();
		}
		message = message.replaceAll("\n", " ");
		return message;
	}
}
