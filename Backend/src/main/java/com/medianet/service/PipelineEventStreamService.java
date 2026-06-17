package com.medianet.service;

import com.medianet.dto.PipelineLogEventDto;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class PipelineEventStreamService {

    private final Map<Long, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final Map<Long, List<PipelineLogEventDto>> buffers = new ConcurrentHashMap<>();

    public SseEmitter createEmitter(Long runId, PipelineLogEventDto initialEvent, boolean completeAfterReplay) {
        SseEmitter emitter = new SseEmitter(600_000L);
        emitters.computeIfAbsent(runId, key -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(runId, emitter));
        emitter.onTimeout(() -> removeEmitter(runId, emitter));
        emitter.onError(error -> removeEmitter(runId, emitter));

        try {
            if (initialEvent != null) {
                emitter.send(SseEmitter.event().data(initialEvent));
            }
            List<PipelineLogEventDto> buffer = buffers.get(runId);
            if (buffer != null) {
                boolean hasComplete = false;
                for (PipelineLogEventDto event : buffer) {
                    emitter.send(SseEmitter.event().data(event));
                    if ("complete".equals(event.type())) {
                        hasComplete = true;
                    }
                }
                if (completeAfterReplay || hasComplete) {
                    emitter.complete();
                    removeEmitter(runId, emitter);
                }
            } else if (completeAfterReplay) {
                emitter.complete();
                removeEmitter(runId, emitter);
            }
        } catch (Exception ignored) {
            removeEmitter(runId, emitter);
        }

        return emitter;
    }

    public void publish(Long runId, PipelineLogEventDto event) {
        buffers.computeIfAbsent(runId, key -> new CopyOnWriteArrayList<>()).add(event);
        List<SseEmitter> listeners = emitters.get(runId);
        if (listeners == null) {
            return;
        }

        for (SseEmitter emitter : listeners) {
            try {
                emitter.send(SseEmitter.event().data(event));
                if ("complete".equals(event.type())) {
                    emitter.complete();
                }
            } catch (Exception ignored) {
                listeners.remove(emitter);
            }
        }
        if ("complete".equals(event.type())) {
            emitters.remove(runId);
        }
    }

    private void removeEmitter(Long runId, SseEmitter emitter) {
        List<SseEmitter> listeners = emitters.get(runId);
        if (listeners != null) {
            listeners.remove(emitter);
            if (listeners.isEmpty()) {
                emitters.remove(runId);
            }
        }
    }
}