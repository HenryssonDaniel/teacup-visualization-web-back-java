package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Properties;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import org.junit.jupiter.api.Test;

class EmailClientTest {
  private static final String FROM = "smtp.from";

  @Test
  void send() throws MessagingException {
    var message = mock(Message.class);

    var properties = mock(Properties.class);
    when(properties.getProperty(FROM)).thenReturn("from");

    var transport = mock(Transport.class);

    var content = "content";
    var subject = "subject";

    new EmailClientImpl(properties).send(content, message, subject, "to", transport);

    verify(message).getAllRecipients();
    verify(message).setFrom(any(InternetAddress.class));
    verify(message).setRecipients(same(RecipientType.TO), any(InternetAddress[].class));
    verify(message).setSubject(subject + " your Teacup account");
    verify(message).setText(content);
    verifyNoMoreInteractions(message);

    verify(properties).getProperty(FROM);
    verifyNoMoreInteractions(properties);

    verify(transport).connect();
    verify(transport).sendMessage(message, null);
    verifyNoMoreInteractions(transport);
  }
}
