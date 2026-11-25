import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, activityEventFixture, ACTIVITY_EVENTS } from './event-fixture.mjs';

// Synthetic fixtures only; no authenticated AWS provenance. Families other than iam and the ACTIVITY_EVENTS keys are
// IAM-shaped events whose eventName is the family name (for synthetic catalog entries in tests).
export function groupedFixture(families = ['iam', 'lambda', 'network'], eventIds = []) {
  return [identityFixture(), ...families.map((family, index) => {
    const options = { blinderSeed: `group-${index}`, eventId: eventIds[index] ?? `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa${index}`,
      mutateEvent(event) { event.userIdentity.arn = 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL'; } };
    const fixture = family === 'iam' ? eventFixture(options) : Object.hasOwn(ACTIVITY_EVENTS, family) ? activityEventFixture(family, options) :
      eventFixture({ ...options, mutateEvent(event) { options.mutateEvent(event); event.eventName = family; }, mutateRow(row) { row.EventName = family; } });
    fixture.expected.sessionId = `33333333-3333-4333-8333-33333333333${index}`;
    fixture.expected.step = `E${index}`;
    fixture.receipt.session.id = fixture.expected.sessionId;
    fixture.receipt.session.step = fixture.expected.step;
    return fixture;
  })];
}
