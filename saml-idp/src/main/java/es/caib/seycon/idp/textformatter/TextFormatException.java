package es.caib.seycon.idp.textformatter;

public class TextFormatException extends Exception
{
	public TextFormatException( String message )
    {
        super( message );
    }
	
	public TextFormatException( Exception exc )
    {
        super( exc );
    }
}
