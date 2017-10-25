package es.caib.seycon.idp.textformatter;

public class TextFormatException extends Exception
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public TextFormatException( String message )
    {
        super( message );
    }
	
	public TextFormatException( Exception exc )
    {
        super( exc );
    }
}
