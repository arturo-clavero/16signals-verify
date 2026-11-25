import { inspectAwsHttpSession, inspectAwsHttpDirections } from './http-session.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { parseCloudTrailStructure } from './nested-json.mjs';
import { awsOperation, AWS_RESOURCE_NAME } from './operation-catalog.mjs';
import { AWS_EVENT_STEPS } from './sessions.mjs';

const fail = () => { throw new Error('AWS_PRIVATE_EVENT_INVALID'); };
const EVENT_KEYS = ['eventVersion', 'eventTime', 'eventID', 'eventName', 'eventSource', 'awsRegion', 'eventType', 'eventCategory',
  'managementEvent', 'readOnly', 'recipientAccountId', 'userIdentity', 'requestParameters', 'responseElements', 'sourceIPAddress',
  'userAgent', 'requestID', 'tlsDetails', 'sessionCredentialFromConsole', 'resources'];
const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;
const privateNode = node => node?.privateSlot !== undefined;
const literal = (node, value) => !privateNode(node) && node?.value === value;
function object(node, allowed, required = []) {
  if (node?.type !== 'object' || node.hasPrivateKeys || node.entries.some(entry => !allowed.includes(entry.key.value))) fail();
  const map = new Map(node.entries.map(entry => [entry.key.value, entry.value]));
  if (required.some(name => !map.has(name))) fail();
  return map;
}

/**
 * Inspect an authenticated event receipt for one operation of the AWS operation catalog.
 * Claims are provisional circuit public outputs, matched to native ranges here.
 * Every returned obligation AND the private identity/event/time/role joins must
 * verify before emitting a claim. This function does not accept an activity proof.
 */
export function inspectAwsEventSession(receipt, expected, atomClaims = [], now = Date.now()) {
  try { return inspectEvent(inspectAwsHttpSession(receipt, expected, now), expected, atomClaims); }
  catch { fail(); }
}

/** Local grammar checks only; never substitute these for authenticated receipt ingestion. */
export function inspectAwsEventDirections(directions, expected, atomClaims = []) {
  try { return inspectEvent(inspectAwsHttpDirections(directions, expected), expected, atomClaims); }
  catch { fail(); }
}

function inspectEvent(http, expected, atomClaims) {
  try {
    if (!AWS_EVENT_STEPS.includes(expected?.step) || !Array.isArray(atomClaims) || atomClaims.length > 512) fail();
    const { sent, recv, native, obligations } = http;
    const claims = new Map(), used = new Set();
    for (const claim of atomClaims) {
      if (!claim || typeof claim !== 'object' || !native.has(key(claim)) || claims.has(key(claim)) ||
          !['outer', 'event'].includes(claim.layer) || !Number.isInteger(claim.kind) || claim.kind < 1 || claim.kind > 5) fail();
      const keys = ['direction', 'start', 'end', 'hash', 'layer', 'kind', ...(claim.layer === 'event' ? ['decodedHash', 'decodedLength'] : [])];
      if (Reflect.ownKeys(claim).length !== keys.length || keys.some(name => !Object.hasOwn(claim, name))) fail();
      claims.set(key(claim), claim);
    }
    const bodySlots = (message, direction) => message.body.privateRanges.map(range => {
      const slot = native.get(key({ direction, start: range.wireStart, end: range.wireEnd, hash: range.hash }));
      const claim = claims.get(key(slot));
      if (!claim || slot.length > 512 || used.has(key(slot)) || (direction === 'SENT' && claim.layer !== 'outer')) fail();
      used.add(key(slot));
      const bridge = claim.layer === 'event';
      obligations.push({ circuitId: bridge ? 'aws-escaped-atom-v1' : 'atom-v1', ...slot, kind: claim.kind,
        ...(bridge ? { decodedHash: claim.decodedHash, decodedLength: claim.decodedLength } : {}) });
      return { layer: claim.layer, start: range.start, end: range.end, hash: range.hash, kind: claim.kind,
        ...(bridge ? { decodedHash: claim.decodedHash, decodedLength: claim.decodedLength } : {}) };
    });
    const requestSlots = bodySlots(sent, 'SENT');
    const request = parseJsonStructure(sent.body.bytes, requestSlots);
    const params = object(request.root, ['LookupAttributes', 'MaxResults'], ['LookupAttributes', 'MaxResults']);
    if (params.get('MaxResults')?.raw !== '1' || params.get('LookupAttributes')?.type !== 'array' ||
        params.get('LookupAttributes').items.length !== 1) fail();
    const attribute = object(params.get('LookupAttributes').items[0], ['AttributeKey', 'AttributeValue'], ['AttributeKey', 'AttributeValue']);
    if (!literal(attribute.get('AttributeKey'), 'EventId') || request.slots.length !== 1 ||
        !privateNode(attribute.get('AttributeValue')) || attribute.get('AttributeValue').kind !== 1) fail();

    const responseSlots = bodySlots(recv, 'RECV');
    const response = parseCloudTrailStructure(recv.body.bytes, responseSlots);
    const row = object(response.outer.entries[0].value.items[0],
      ['CloudTrailEvent', 'EventId', 'EventName', 'EventSource', 'EventTime', 'ReadOnly', 'Username', 'AccessKeyId', 'Resources'],
      ['CloudTrailEvent', 'EventId', 'EventName', 'EventSource', 'EventTime']);
    const top = name => response.event?.entries?.find(entry => entry.key.value === name)?.value;
    const operation = awsOperation(top('eventSource')?.value, top('eventName')?.value);
    if (!operation) fail();
    const extraKeys = Object.keys(operation.event?.object ?? {});
    if (extraKeys.some(name => EVENT_KEYS.includes(name))) fail();
    const event = object(response.event, [...EVENT_KEYS, ...extraKeys], ['eventVersion', 'eventTime', 'eventID', 'eventName',
      'eventSource', 'awsRegion', 'eventType', 'eventCategory', 'managementEvent', 'readOnly', 'recipientAccountId', 'userIdentity',
      'requestParameters', 'responseElements']);
    const publicFields = { eventName: event.get('eventName').value, eventSource: operation.eventSource, awsRegion: 'us-east-1',
      eventType: 'AwsApiCall', eventCategory: 'Management', managementEvent: true, readOnly: operation.readOnly };
    for (const [name, value] of Object.entries(publicFields)) if (!literal(event.get(name), value)) fail();
    if (privateNode(event.get('eventVersion')) || event.get('eventVersion')?.type !== 'string' ||
        !/^1\.[0-9]{2}$/.test(event.get('eventVersion').value) ||
        !literal(row.get('EventName'), publicFields.eventName) || !literal(row.get('EventSource'), publicFields.eventSource) ||
        (row.has('ReadOnly') && !literal(row.get('ReadOnly'), 'false'))) fail();

    const field = (node, slots, kind = 1) => {
      if (!privateNode(node) || node.kind !== kind || !slots[node.privateSlot]) fail();
      return slots[node.privateSlot];
    };
    const outerAtoms = response.outerAtoms;
    const innerAtoms = response.eventAtoms.map(atom => atom.decoded);
    const innerField = (node, kind) => field(node, innerAtoms, kind);
    const actor = object(event.get('userIdentity'), ['type', 'principalId', 'arn', 'accountId', 'userName', 'accessKeyId', 'sessionContext'],
      ['type', 'principalId', 'arn', 'accountId']);
    if (!literal(actor.get('type'), 'IAMUser')) fail();
    for (const name of ['userName', 'accessKeyId']) if (actor.has(name)) innerField(actor.get(name));
    if (actor.has('sessionContext')) {
      const context = object(actor.get('sessionContext'), ['attributes'], ['attributes']);
      const attributes = object(context.get('attributes'), ['creationDate', 'mfaAuthenticated']);
      for (const node of attributes.values()) innerField(node);
    }
    const walk = (node, spec) => {
      if (spec.atom !== undefined) {
        if (!privateNode(node) || ![spec.atom].flat().includes(node.kind)) fail();
        const slot = innerField(node, node.kind);
        if (spec.minBytes !== undefined && slot.end - slot.start < spec.minBytes) fail();
      } else if (spec.literal !== undefined) {
        if (!literal(node, spec.literal)) fail();
      } else if (spec.object) {
        if (spec.nullable && literal(node, null)) return;
        const map = object(node, Object.keys(spec.object), spec.required);
        if (spec.atLeastOne && !spec.atLeastOne.some(name => map.has(name))) fail();
        for (const [name, child] of map) walk(child, spec.object[name]);
        return map;
      } else if (spec.array !== undefined) {
        if (node?.type !== 'array' || (spec.array === null ? node.items.length : spec.nonEmpty && !node.items.length)) fail();
        for (const item of node.items) walk(item, spec.array);
      } else {
        const list = object(node, ['items'], spec.nonEmpty ? ['items'] : []).get('items');
        if (list === undefined) return;
        if (list.type !== 'array' || (spec.nonEmpty && !list.items.length)) fail();
        for (const item of list.items) walk(item, spec.list);
      }
    };
    const parameters = walk(event.get('requestParameters'), operation.request);
    walk(event.get('responseElements'), operation.response);
    for (const name of extraKeys) if (event.has(name)) walk(event.get(name), operation.event.object[name]);
    // Reuse the pinned name circuit's bounded ASCII grammar for these resource names.
    // This is deliberately narrower than all Lambda resource ARN forms.
    const roleName = innerField(parameters.get(operation.resource));
    if (roleName.end - roleName.start < AWS_RESOURCE_NAME.minBytes || roleName.end - roleName.start > AWS_RESOURCE_NAME.maxBytes) fail();
    for (const name of ['sourceIPAddress', 'userAgent', 'requestID', 'sessionCredentialFromConsole']) {
      if (event.has(name)) innerField(event.get(name));
    }
    for (const name of ['Username', 'AccessKeyId']) if (row.has(name)) field(row.get(name), outerAtoms);
    if (event.has('tlsDetails')) {
      const tls = object(event.get('tlsDetails'), ['tlsVersion', 'cipherSuite', 'clientProvidedHostHeader', 'keyExchange']);
      for (const node of tls.values()) innerField(node);
    }
    for (const [node, names, slots] of [[row.get('Resources'), ['ResourceType', 'ResourceName'], outerAtoms],
      [event.get('resources'), ['ARN', 'accountId', 'type'], innerAtoms]]) {
      if (node === undefined) continue;
      if (node.type !== 'array') fail();
      for (const resource of node.items) for (const value of object(resource, names).values()) field(value, slots);
    }
    if (used.size !== claims.size || obligations.length !== native.size || new Set(obligations.map(key)).size !== native.size) fail();
    return { activity: operation.id, obligations, bindings: {
      requestEventId: field(attribute.get('AttributeValue'), request.slots), outerEventId: field(row.get('EventId'), outerAtoms),
      eventId: innerField(event.get('eventID')), outerTime: field(row.get('EventTime'), outerAtoms, 2), eventTime: innerField(event.get('eventTime')),
      recipientAccount: innerField(event.get('recipientAccountId')), actorAccount: innerField(actor.get('accountId')),
      actorId: innerField(actor.get('principalId')), actorArn: innerField(actor.get('arn')), roleName,
      ...(event.has('userAgent') ? { userAgent: innerField(event.get('userAgent')) } : {}),
    } };
  } catch { throw new Error('AWS_PRIVATE_EVENT_INVALID'); }
}
