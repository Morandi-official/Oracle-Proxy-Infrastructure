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
    static final long TARGET_NANOS = TimeUnit.MILLISECONDS.toNanos(1000);

    private final Instrumentation instrumentation;
    private final MainActivity screen;
    private final AppController controller;
    private final Predicate<AppController.State> verified;
    private final CountDownLatch visible = new CountDownLatch(1);
    private final Rect visibleStatus = new Rect();
    private final ViewTreeObserver.OnDrawListener drawn = this::onDraw;
    private final ViewTreeObserver.OnWindowFocusChangeListener focus = this::onFocusChanged;
    private final String diagnosticLabel;
    private ViewTreeObserver tree;
    private View connectButton;
    private volatile long downSubmitted;
    private volatile long started;
    private long downReturned;
    private long upReturned;
    private long appDownDelivered;
    private long appUpDelivered;
    private long focusGained;
    private long firstVerifiedDraw;
    private int firstDrawFocused = -1;
    private long duration;

    VisibleConnectionTiming(String diagnosticLabel, Instrumentation instrumentation, MainActivity screen,
                            AppController controller, Predicate<AppController.State> verified) {
        this.diagnosticLabel = diagnosticLabel;
        this.instrumentation = instrumentation;
        this.screen = screen;
        this.controller = controller;
        this.verified = verified;
        instrumentation.runOnMainSync(() -> {
            tree = screen.getWindow().getDecorView().getViewTreeObserver();
            tree.addOnDrawListener(drawn);
            tree.addOnWindowFocusChangeListener(focus);
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
            connectButton = connect;
            connect.setOnTouchListener((view, event) -> {
                if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
                    appDownDelivered = SystemClock.elapsedRealtimeNanos();
                } else if (event.getActionMasked() == MotionEvent.ACTION_UP) {
                    appUpDelivered = SystemClock.elapsedRealtimeNanos();
                }
                // Let the existing view deliver its normal click action.
                return false;
            });
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
            long submitted = SystemClock.elapsedRealtimeNanos();
            if (action == MotionEvent.ACTION_DOWN) {
                downSubmitted = submitted;
            } else {
                started = submitted;
            }
            boolean injected = instrumentation.getUiAutomation().injectInputEvent(event, true);
            long returned = SystemClock.elapsedRealtimeNanos();
            if (action == MotionEvent.ACTION_DOWN) {
                downReturned = returned;
            } else {
                upReturned = returned;
            }
            assertTrue("Android accepted the touchscreen input", injected);
        } finally {
            event.recycle();
        }
    }

    private void onFocusChanged(boolean focused) {
        if (focused && started != 0 && visible.getCount() != 0 && focusGained == 0) {
            focusGained = SystemClock.elapsedRealtimeNanos();
        }
    }

    private void onDraw() {
        long start = started;
        if (start == 0 || visible.getCount() == 0 || !verified.test(controller.snapshot())) {
            return;
        }
        TextView status = screen.findViewById(R.id.connection_status);
        if (status != null && status.isShown() && status.getLocalVisibleRect(visibleStatus)
                && "已连接".contentEquals(status.getText())) {
            long now = SystemClock.elapsedRealtimeNanos();
            boolean focused = screen.hasWindowFocus();
            if (firstVerifiedDraw == 0) {
                firstVerifiedDraw = now;
                firstDrawFocused = focused ? 1 : 0;
            }
            if (focused) {
                duration = now - start;
                visible.countDown();
            }
        }
    }

    long await(String label) throws InterruptedException {
        assertTrue(label + " drew a reachable verified connection status",
                visible.await(65, TimeUnit.SECONDS));
        return duration;
    }

    static void report(String label, long duration) {
        android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_" + label + "_MS="
                + TimeUnit.NANOSECONDS.toMillis(duration) + ";TARGET_MS=1000;UNDER_TARGET="
                + (duration <= TARGET_NANOS ? 1 : 0));
    }

    @Override public void close() {
        instrumentation.runOnMainSync(() -> {
            if (connectButton != null) {
                connectButton.setOnTouchListener(null);
            }
            if (tree.isAlive()) {
                tree.removeOnDrawListener(drawn);
                tree.removeOnWindowFocusChangeListener(focus);
            }
            if (started != 0) {
                android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_VISUAL_DIAGNOSTICS_" + diagnosticLabel
                        + "=DOWN_CALL_NS:" + offset(downSubmitted, downReturned)
                        + ";UP_CALL_NS:" + offset(started, upReturned)
                        + ";APP_DOWN_DELIVERY_NS:" + offset(downSubmitted, appDownDelivered)
                        + ";APP_UP_DELIVERY_NS:" + offset(started, appUpDelivered)
                        + ";CONSENT_RESULT_NS:" + offset(started, screen.vpnConsentResultNanos())
                        + ";FOCUS_GAIN_NS:" + offset(started, focusGained)
                        + ";FIRST_VERIFIED_DRAW_NS:" + offset(started, firstVerifiedDraw)
                        + ";FIRST_DRAW_FOCUSED:" + firstDrawFocused
                        + ";FOCUSED_DRAW_NS:" + (visible.getCount() == 0 ? duration : -1));
            }
        });
    }

    private static long offset(long start, long event) {
        return start == 0 || event < start ? -1 : event - start;
    }
}
