package org.morandi.proxy;

import android.app.Instrumentation;
import android.graphics.Rect;
import android.os.SystemClock;
import android.view.InputDevice;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.TextView;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** Times a touchscreen release through the first view draw of the verified status. */
final class VisibleConnectionTiming implements AutoCloseable {
    static final long TARGET_NANOS = TimeUnit.MILLISECONDS.toNanos(1500);

    private final Instrumentation instrumentation;
    private final MainActivity screen;
    private final AppController controller;
    private final Predicate<AppController.State> verified;
    private final CountDownLatch visible = new CountDownLatch(1);
    private final Rect visibleStatus = new Rect();
    private final ViewTreeObserver.OnDrawListener drawn = this::onDraw;
    private ViewTreeObserver tree;
    private volatile long started;
    private long duration;

    VisibleConnectionTiming(Instrumentation instrumentation, MainActivity screen,
                            AppController controller, Predicate<AppController.State> verified) {
        this.instrumentation = instrumentation;
        this.screen = screen;
        this.controller = controller;
        this.verified = verified;
        instrumentation.runOnMainSync(() -> {
            tree = screen.getWindow().getDecorView().getViewTreeObserver();
            tree.addOnDrawListener(drawn);
        });
    }

    void tapConnectButton() {
        instrumentation.waitForIdleSync();
        Rect bounds = new Rect();
        instrumentation.runOnMainSync(() -> {
            View connect = screen.findViewById(R.id.connect);
            assertNotNull("The Connect action is present", connect);
            assertTrue("The Connect action is enabled", connect.isEnabled());
            assertTrue("The Connect action is visible", connect.getLocalVisibleRect(bounds));
            int[] position = new int[2];
            connect.getLocationOnScreen(position);
            bounds.offset(position[0], position[1]);
        });
        tap(bounds);
    }

    void tap(Rect bounds) {
        assertTrue("Tap target has a visible area", !bounds.isEmpty());
        long down = SystemClock.uptimeMillis();
        inject(down, MotionEvent.ACTION_DOWN, bounds);
        inject(down, MotionEvent.ACTION_UP, bounds);
    }

    private void inject(long down, int action, Rect bounds) {
        MotionEvent event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action,
                bounds.exactCenterX(), bounds.exactCenterY(), 0);
        event.setSource(InputDevice.SOURCE_TOUCHSCREEN);
        try {
            if (action == MotionEvent.ACTION_UP) {
                started = SystemClock.elapsedRealtimeNanos();
            }
            assertTrue("Android accepted the touchscreen input",
                    instrumentation.getUiAutomation().injectInputEvent(event, true));
        } finally {
            event.recycle();
        }
    }

    private void onDraw() {
        long start = started;
        if (start == 0 || visible.getCount() == 0 || !screen.hasWindowFocus()
                || !verified.test(controller.snapshot())) {
            return;
        }
        TextView status = screen.findViewById(R.id.connection_status);
        if (status != null && status.isShown() && status.getLocalVisibleRect(visibleStatus)
                && "已连接".contentEquals(status.getText())) {
            duration = SystemClock.elapsedRealtimeNanos() - start;
            visible.countDown();
        }
    }

    long await(String label) throws InterruptedException {
        assertTrue(label + " drew a reachable verified connection status",
                visible.await(65, TimeUnit.SECONDS));
        return duration;
    }

    static void report(String label, long duration) {
        android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_" + label + "_MS="
                + TimeUnit.NANOSECONDS.toMillis(duration) + ";TARGET_MS=1500;UNDER_TARGET="
                + (duration <= TARGET_NANOS ? 1 : 0));
    }

    @Override public void close() {
        instrumentation.runOnMainSync(() -> {
            if (tree.isAlive()) {
                tree.removeOnDrawListener(drawn);
            }
        });
    }
}
