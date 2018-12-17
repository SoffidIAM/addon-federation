package com.soffid.iam.addons.federation.web;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Page;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.EventListener;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Checkbox;
import org.zkoss.zul.Grid;
import org.zkoss.zul.Row;

import es.caib.zkib.binder.SingletonBinder;
import es.caib.zkib.events.XPathEvent;
import es.caib.zkib.events.XPathRerunEvent;
import es.caib.zkib.events.XPathSubscriber;

public class AuthenticationGrid extends Grid implements XPathSubscriber, AfterCompose {
	SingletonBinder binder = new SingletonBinder(this);
	private EventListener onCheckListener = new EventListener() {
		public void onEvent(Event event) throws Exception {
			HashSet<String> enabled = new HashSet<String>();
			StringBuffer sb = new StringBuffer();
			for (Checkbox cb: findCheckboxes())
			{
				String type = (String) cb.getAttribute("type");
				if ( enabled.contains(type.substring(0, 1)))
				{
					cb.setDisabled(true);
				}
				else
				{
					cb.setDisabled(false);
					if (cb.isChecked())
					{
						if (sb.length() > 0)
							sb.append(' ');
						sb.append( type);
					}
				}
			}
			binder.setValue(sb.toString());
		}
	};
	
	public void setPage(Page page) {
		super.setPage(page);
		binder.setPage(page);
	}

	public void setParent(Component parent) {
		super.setParent(parent);
		binder.setParent(parent);
	}

	public void onUpdate(XPathEvent event) {
		HashSet<String> tags = new HashSet<String>( );
		String v = (String) binder.getValue();
		if (v != null)
			for (String tag: v.split(" ")) tags.add(tag);
		HashSet<String> enabled = new HashSet<String>();
		for (Checkbox cb: findCheckboxes())
		{
			String tag = (String) cb.getAttribute("type");
			cb.setChecked(tags.contains(tag));
			if ( enabled.contains(tag.substring(0, 1)))
			{
				cb.setChecked(false);
				cb.setDisabled(true);
			}
			else
			{
				cb.setDisabled(false);
				if (tags.contains(tag))
				{
					cb.setChecked(true);
					enabled.add(tag);
				}
				else
				{
					cb.setChecked(false);
				}
			}
		}
	}

	public void afterCompose() {
		for (Checkbox cb: findCheckboxes())
		{
			cb.addEventListener("onCheck", onCheckListener );
		}
	}
	
	public Collection<Checkbox> findCheckboxes()
	{
		List<Checkbox> result = new LinkedList<Checkbox>();
		for ( Row r: (Collection<Row>) getRows().getChildren())
		{
			for (Component component: (Collection<Component>) r.getChildren())
			{
				if (component instanceof Checkbox)
				{
					result.add((Checkbox) component);
				}
			}
		}
		return result;
	}

	public void setBind(String s)
	{
		binder.setDataPath(s);
	}
}

