package org.morandi.proxy;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class ClientApiTransportTest {
    private static final String HOST = "vpn-admin.morandi.dpdns.org";
    private static final String TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String PROBE = "{\"error\":\"INVALID_REQUEST\"}";
    private static final MediaType JSON = MediaType.get("application/json");

    @Test
    public void slowOrdinaryRouteCannotBlockProvenBootstrapAndEnrollReusesIt() throws Exception {
        List<Exchange> ordinaryRequests = new CopyOnWriteArrayList<>();
        List<Exchange> bootstrapRequests = new CopyOnWriteArrayList<>();
        CountDownLatch ordinaryStarted = new CountDownLatch(1);
        CountDownLatch releaseOrdinary = new CountDownLatch(1);
        AtomicBoolean ordinaryFinished = new AtomicBoolean();
        ClientApi api = new ClientApi(fixture(chain -> {
            observe(chain, ordinaryRequests);
            ordinaryStarted.countDown();
            try {
                require(releaseOrdinary);
            } finally {
                ordinaryFinished.set(true);
            }
            throw new SocketTimeoutException("fixture ordinary route");
        }), fixture(chain -> {
            Exchange exchange = observe(chain, bootstrapRequests);
            if ("{}".equals(exchange.body)) {
                require(ordinaryStarted);
                return response(chain.request(), 400, PROBE);
            }
            return response(chain.request(), 200, "{\"ok\":true}");
        }));

        JSONObject signIn = signInBody();
        JSONObject enrollment = new JSONObject().put("device_name", "Fixture").put("confirm", true);
        try {
            assertTrue(api.call("authenticate", "", signIn).getBoolean("ok"));
            assertFalse("A proven bootstrap route wins while the ordinary request still waits", ordinaryFinished.get());
            assertTrue(api.call("enroll", TOKEN, enrollment).getBoolean("ok"));
            assertEquals(1, ordinaryRequests.size());
            assertEquals(3, bootstrapRequests.size());
            assertProbe(ordinaryRequests.get(0));
            assertProbe(bootstrapRequests.get(0));
            assertPost(bootstrapRequests.get(1), "authenticate", null, signIn);
            assertPost(bootstrapRequests.get(2), "enroll", "Bearer " + TOKEN, enrollment);
        } finally {
            releaseOrdinary.countDown();
        }
    }

    @Test
    public void transportFailureDuringPasswordPostDoesNotReplayIt() throws Exception {
        List<Exchange> ordinaryRequests = new CopyOnWriteArrayList<>();
        List<Exchange> bootstrapRequests = new CopyOnWriteArrayList<>();
        CountDownLatch ordinaryStarted = new CountDownLatch(1);
        ClientApi api = new ClientApi(fixture(chain -> {
            observe(chain, ordinaryRequests);
            ordinaryStarted.countDown();
            throw new UnknownHostException("fixture DNS failure");
        }), fixture(chain -> {
            Exchange exchange = observe(chain, bootstrapRequests);
            if ("{}".equals(exchange.body)) {
                require(ordinaryStarted);
                return response(chain.request(), 400, PROBE);
            }
            // We observed the complete password body before the transport failed.
            throw new IOException("fixture interrupted after password upload");
        }));

        JSONObject signIn = signInBody();
        ClientApi.ApiError failure = assertThrows(ClientApi.ApiError.class,
                () -> api.call("authenticate", "", signIn));
        assertEquals("ACCOUNT_API_UNREACHABLE", failure.code);
        assertEquals(1, ordinaryRequests.size());
        assertProbe(ordinaryRequests.get(0));
        assertEquals(2, bootstrapRequests.size());
        assertProbe(bootstrapRequests.get(0));
        assertPost(bootstrapRequests.get(1), "authenticate", null, signIn);
    }

    @Test
    public void restoredStateSendsItsBearerOnlyAfterAnonymousRouteProof() throws Exception {
        List<Exchange> ordinaryRequests = new CopyOnWriteArrayList<>();
        List<Exchange> bootstrapRequests = new CopyOnWriteArrayList<>();
        ClientApi api = new ClientApi(fixture(chain -> {
            observe(chain, ordinaryRequests);
            return response(chain.request(), 401, "{\"error\":\"LOGIN_REQUIRED\"}");
        }), fixture(chain -> {
            Exchange exchange = observe(chain, bootstrapRequests);
            if ("{}".equals(exchange.body)) return response(chain.request(), 400, PROBE);
            return response(chain.request(), 200, "{\"ok\":true}");
        }));

        assertTrue(api.call("state", TOKEN, null).getBoolean("ok"));
        for (Exchange request : ordinaryRequests) assertProbe(request);
        assertEquals(2, bootstrapRequests.size());
        assertProbe(bootstrapRequests.get(0));
        Exchange restoredState = bootstrapRequests.get(1);
        assertOrigin(restoredState, "state");
        assertEquals("GET", restoredState.method);
        assertEquals("Bearer " + TOKEN, restoredState.authorization);
        assertNull(restoredState.body);
        assertFalse(restoredState.oneShot);
    }

    @Test
    public void incorrectProbeResponsesNeverReceiveCredentials() throws Exception {
        List<Exchange> requests = new CopyOnWriteArrayList<>();
        ClientApi api = new ClientApi(fixture(chain -> {
            observe(chain, requests);
            return response(chain.request(), 200, PROBE);
        }), fixture(chain -> {
            observe(chain, requests);
            return response(chain.request(), 400, "{\"error\":\"LOGIN_REQUIRED\"}");
        }));
        ClientApi.ApiError failure = assertThrows(ClientApi.ApiError.class,
                () -> api.call("authenticate", "", signInBody()));
        assertEquals("API_UNAVAILABLE", failure.code);
        assertEquals(2, requests.size());
        for (Exchange request : requests) assertProbe(request);
    }

    private static OkHttpClient fixture(Interceptor interceptor) {
        return new OkHttpClient.Builder().addInterceptor(interceptor).build();
    }

    private static JSONObject signInBody() throws Exception {
        return new JSONObject().put("username", "fixture").put("password", "fixture-only")
                .put("public_key", "fixture-public-key").put("device_name", "Fixture")
                .put("client_version", "0.0.0-fixture");
    }

    private static void require(CountDownLatch condition) throws IOException {
        try {
            if (!condition.await(5, TimeUnit.SECONDS)) throw new IOException("fixture blocked");
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException(error);
        }
    }

    private static Response response(Request request, int status, String body) {
        return new Response.Builder().request(request).protocol(Protocol.HTTP_1_1)
                .code(status).message("fixture").body(ResponseBody.create(body, JSON)).build();
    }

    private record Exchange(Request request, String method, String authorization, String body, boolean oneShot) {}

    private static Exchange observe(Interceptor.Chain chain, List<Exchange> requests) throws IOException {
        Request request = chain.request();
        RequestBody body = request.body();
        Buffer buffer = new Buffer();
        if (body != null) body.writeTo(buffer);
        Exchange exchange = new Exchange(request, request.method(), request.header("Authorization"),
                body == null ? null : buffer.readUtf8(), body != null && body.isOneShot());
        requests.add(exchange);
        return exchange;
    }

    private static void assertOrigin(Exchange exchange, String action) {
        assertEquals("https", exchange.request.url().scheme());
        assertEquals(HOST, exchange.request.url().host());
        assertEquals("/api/client/" + action, exchange.request.url().encodedPath());
    }

    private static void assertProbe(Exchange exchange) {
        assertOrigin(exchange, "authenticate");
        assertEquals("POST", exchange.method);
        assertEquals("{}", exchange.body);
        assertNull(exchange.authorization);
        assertTrue(exchange.oneShot);
    }

    private static void assertPost(Exchange exchange, String action, String authorization, JSONObject body) {
        assertOrigin(exchange, action);
        assertEquals("POST", exchange.method);
        assertEquals(authorization, exchange.authorization);
        assertEquals(body.toString(), exchange.body);
        assertTrue(exchange.oneShot);
    }
}
