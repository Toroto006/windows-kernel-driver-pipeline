const backendUrl = "http://COORDINATOR_IP:5000"
// TODO FIX the blocked: mixed content issue, i.e. make the backend serve https

export function updateFilename(id: number, newFilename: string) {
    const response = fetch(`${backendUrl}/files/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            'filename': newFilename,
        }),
    });

    return response
}

export function updateDriverTag(id: number, newTag: string) {
    const response = fetch(`${backendUrl}/driver-tags/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            'tag': newTag,
        }),
    });

    return response
}

import { FuzzingQueueElem } from '@/types/FuzzingQueue'
export function addFuzzingQueue(queueElem: FuzzingQueueElem) {
    let data : { [id: string] : string | number | number[] } = {
        'driver': queueElem.driver,
        'priority': queueElem.priority,
        //'seeds': queueElem.seeds, // TODO: Implement seeds
    };
    if ( queueElem.max_runtime ) {
        data['max_runtime'] = queueElem.max_runtime
    }
    if ( queueElem.max_last_crash ) {
        data['max_last_crash'] = queueElem.max_last_crash
    }
    if ( queueElem.max_last_any ) {
        data['max_last_any'] = queueElem.max_last_any
    }
    if ( queueElem.dos_device_str ) {
        data['dos_device_str'] = queueElem.dos_device_str
    }

    const response = fetch(`${backendUrl}/fuzzing-queue`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    return response
}
