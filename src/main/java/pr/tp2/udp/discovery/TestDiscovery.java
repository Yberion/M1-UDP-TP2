package pr.tp2.udp.discovery;

import org.tinylog.Logger;

import java.io.IOException;

public class TestDiscovery {
    public static void main(String[] args) throws InterruptedException, IOException {
        Runnable listener = () ->
        {
            try {
                Discovery.listenAndReply();
            } catch (IOException e) {
                Logger.trace(e);
            }
        };

        new Thread(listener).start();

        // Wait a bit before sending anything, so everything is properly initialized
        Thread.sleep(1000);

        Discovery.sendWhois("051005022");
        Discovery.sendIAM("tftp", "127.0.0.1:6969");

        Thread.sleep(10000);
    }
}
