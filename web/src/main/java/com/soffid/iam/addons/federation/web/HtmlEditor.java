package com.soffid.iam.addons.federation.web;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Execution;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Page;
import org.zkoss.zk.ui.WrongValueException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.EventListener;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Html;
import org.zkoss.zul.Window;
import org.zkoss.zul.impl.InputElement;

import com.soffid.codemirror.Codemirror;

public class HtmlEditor extends Window implements AfterCompose {
	private InputElement textbox;
	private Codemirror editor;
	
	public static void edit ( InputElement textbox, String vars) {
		edit (textbox);
	}
	
	public static void edit ( InputElement textbox) {
		Page p = textbox.getPage();
		Component editorWindow = (Component) p.getFellowIfAny("editorWindow");
		if (editorWindow != null) 
			editorWindow.detach();
		
		Map args = new HashMap();
		args.put("textbox", textbox);
		Executions.createComponents("/addon/federation/popup/editorhtml.zul", null, args );
	}
	
	@Override
	public void setPage (Page page) {
		super.setPage(page);
		Execution ex = Executions.getCurrent();
		Map args = ex.getArg();
		this.textbox = (InputElement) args.get("textbox");
	}
	
	public void cleanWindow(Event event) throws WrongValueException, Exception {
		editor.setValue("");
		detach();
	}

	public void accept(Event event) throws WrongValueException, Exception {
		textbox.setText(editor.getValue());
		cleanWindow(event);
	}

	@Override
	public void afterCompose() {
		editor = (Codemirror) getFellow("editor");
		editor.setLanguage("html");
		editor.setValue( textbox.getText() );
		editor.focus();
	}

}
