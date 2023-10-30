package seedu.address.model.transaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static seedu.address.testutil.Assert.assertThrows;
import static seedu.address.testutil.TypicalPersons.ALICE;
import static seedu.address.testutil.TypicalPersons.BENSON;
import static seedu.address.testutil.TypicalPersons.BOB;
import static seedu.address.testutil.TypicalPersons.CARL;
import static seedu.address.testutil.TypicalPersons.DANIEL;
import static seedu.address.testutil.TypicalPortions.ALICE_PORTION;
import static seedu.address.testutil.TypicalPortions.BENSON_PORTION;
import static seedu.address.testutil.TypicalPortions.CARL_PORTION;
import static seedu.address.testutil.TypicalPortions.SELF_PORTION;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.numbers.fraction.BigFraction;
import org.junit.jupiter.api.Test;

import seedu.address.model.person.Name;
import seedu.address.model.person.Person;
import seedu.address.model.transaction.portion.Portion;
import seedu.address.testutil.PersonBuilder;
import seedu.address.testutil.PortionBuilder;
import seedu.address.testutil.TransactionBuilder;

class TransactionTest {

    @Test
    public void asObservableList_modifyList_throwsUnsupportedOperationException() {
        Transaction transaction = new TransactionBuilder().build();
        assertThrows(UnsupportedOperationException.class, () -> transaction.getPortions().remove(0));
    }

    @Test
    public void isSameTransaction() {
        Transaction transaction = new TransactionBuilder().build();

        // same values but different objects -> returns true
        assertTrue(transaction.isSameTransaction(
                new TransactionBuilder().withTimestamp(transaction.getTimestamp().toString()).build()));

        // different timestamps -> returns false
        assertFalse(transaction.isSameTransaction(
                new TransactionBuilder().withTimestamp("13/10/2023 12:34").build()));

        // same object -> returns true
        assertTrue(transaction.isSameTransaction(transaction));

        // null -> returns false
        assertFalse(transaction.isSameTransaction(null));

        // different amount -> returns false
        assertFalse(transaction.isSameTransaction(new TransactionBuilder().withAmount("100").build()));

        // different description -> returns false
        assertFalse(transaction.isSameTransaction(new TransactionBuilder().withDescription("Description").build()));

        // different payeeName -> returns false
        assertFalse(transaction.isSameTransaction(
                new TransactionBuilder().withPayeeName(BOB.getName().fullName).build()));

        // different portions -> returns false
        Set<Portion> portions = Set.of(BENSON_PORTION);
        assertFalse(transaction.isSameTransaction(new TransactionBuilder().withPortions(portions).build()));
    }

    @Test
    public void equals() {
        Transaction transaction = new TransactionBuilder().build();

        // same values but different objects -> returns true
        assertEquals(transaction, new TransactionBuilder().withTimestamp(
                transaction.getTimestamp().toString()).build());

        // different timestamps -> returns false
        assertNotEquals(transaction, new TransactionBuilder().withTimestamp("13/10/2023 12:34").build());

        // same object -> returns true
        assertEquals(transaction, transaction);

        // null -> returns false
        assertNotEquals(null, transaction);

        // different types -> returns false
        assertNotEquals(transaction, 5.0f);

        // different amount -> returns false
        assertNotEquals(transaction, new TransactionBuilder().withAmount("100").build());

        // different description -> returns false
        assertNotEquals(transaction, new TransactionBuilder().withDescription("Description").build());

        // different payee -> returns false
        assertNotEquals(transaction, new TransactionBuilder().withPayeeName(BOB.getName().fullName).build());

        // different portions -> returns false
        Set<Portion> portions = Set.of(BENSON_PORTION);
        assertNotEquals(transaction, new TransactionBuilder().withPortions(portions).build());
    }

    @Test
    public void toStringTest() {
        Transaction transaction = new TransactionBuilder().build();
        String expected = Transaction.class.getCanonicalName() + "{amount=" + transaction.getAmount()
            + ", description=" + transaction.getDescription() + ", payeeName=" + transaction.getPayeeName()
            + ", portions=" + transaction.getPortions() + "}";
        assertEquals(expected, transaction.toString());
    }

    @Test
    public void isPersonInvolved_payerInTransaction_returnsTrue() {
        Set<Portion> portions = Set.of(ALICE_PORTION, CARL_PORTION);
        Transaction transaction = new TransactionBuilder()
            .withPayeeName(BOB.getName().fullName).withPortions(portions).build();
        assertTrue(transaction.isPersonInvolved(ALICE.getName()));
        assertTrue(transaction.isPersonInvolved(CARL.getName()));
    }

    @Test
    public void isPersonInvolved_payeeInTransaction_returnsTrue() {
        Set<Portion> portions = Set.of(ALICE_PORTION, CARL_PORTION);
        Transaction transaction = new TransactionBuilder()
            .withPayeeName(BOB.getName().fullName).withPortions(portions).build();
        assertTrue(transaction.isPersonInvolved(BOB.getName()));
    }

    @Test
    public void isPersonInvolved_personNotInTransaction_returnsFalse() {
        Set<Portion> portions = Set.of(ALICE_PORTION, CARL_PORTION);
        Transaction transaction = new TransactionBuilder()
            .withPayeeName(BOB.getName().fullName).withPortions(portions).build();
        assertFalse(transaction.isPersonInvolved(DANIEL.getName()));
    }

    @Test
    public void getAllInvolvedPersonNames_transactionWithPayerAndPayee_returnsCorrectNames() {
        Set<Portion> portions = Set.of(ALICE_PORTION, CARL_PORTION);
        Transaction transaction = new TransactionBuilder()
            .withPayeeName(BENSON.getName().fullName).withPortions(portions).build();
        assertEquals(Set.of(ALICE.getName(), CARL.getName(), BENSON.getName()),
            transaction.getAllInvolvedPersonNames());
    }

    @Test
    public void getPortion_singlePortion_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(ALICE_PORTION);
        Transaction transaction = new TransactionBuilder().withAmount("100").withPortions(portions).build();
        BigFraction expectedPortion = BigFraction.of(100, 1);
        assertEquals(expectedPortion, transaction.getPortionAmount(ALICE.getName()));
    }

    @Test
    public void getPortion_multiplePortions_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(
            ALICE_PORTION,
            BENSON_PORTION,
            CARL_PORTION
        );
        Transaction transaction = new TransactionBuilder().withAmount("600").withPortions(portions).build();
        assertEquals(BigFraction.of(100, 1),
                transaction.getPortionAmount(ALICE.getName()));
        assertEquals(BigFraction.of(200, 1),
                transaction.getPortionAmount(BENSON.getName()));
        assertEquals(BigFraction.of(300, 1),
                transaction.getPortionAmount(CARL.getName()));
    }

    @Test
    public void getPortionOwed_otherPayeeSinglePortion_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(ALICE_PORTION);
        Transaction transaction = new TransactionBuilder().withPayeeName(ALICE.getName().fullName)
                .withAmount("100").withPortions(portions).build();
        assertEquals(BigFraction.ZERO, transaction.getPortionAmountOwedSelf(ALICE.getName()));
    }

    @Test
    public void getPortionOwed_otherPayeeMultiplePortions_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(
            ALICE_PORTION,
            BENSON_PORTION,
            CARL_PORTION,
            SELF_PORTION
        );
        Transaction transaction = new TransactionBuilder().withPayeeName(ALICE.getName().fullName)
                .withAmount("1000").withPortions(portions).build();
        assertEquals(BigFraction.of(-400, 1), transaction.getPortionAmountOwedSelf(ALICE.getName()));
        assertEquals(BigFraction.ZERO, transaction.getPortionAmountOwedSelf(BENSON.getName()));
        assertEquals(BigFraction.ZERO, transaction.getPortionAmountOwedSelf(CARL.getName()));
        assertEquals(BigFraction.ZERO, transaction.getPortionAmountOwedSelf(Name.SELF));
    }
    @Test
    public void getPortionOwed_selfPayeeSinglePortion_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(ALICE_PORTION);
        Transaction transaction = new TransactionBuilder().withPayeeName(Name.SELF.fullName)
                .withAmount("100").withPortions(portions).build();
        BigFraction expectedPortion = BigFraction.of(100, 1);
        assertEquals(expectedPortion, transaction.getPortionAmountOwedSelf(ALICE.getName()));
    }

    @Test
    public void getPortionOwed_selfPayeeMultiplePortions_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(
            ALICE_PORTION,
            BENSON_PORTION,
            CARL_PORTION,
            SELF_PORTION
        );
        Transaction transaction = new TransactionBuilder().withPayeeName(Name.SELF.fullName)
                .withAmount("1000").withPortions(portions).build();
        assertEquals(BigFraction.of(100, 1),
                transaction.getPortionAmountOwedSelf(ALICE.getName()));
        assertEquals(BigFraction.of(200, 1),
                transaction.getPortionAmountOwedSelf(BENSON.getName()));
        assertEquals(BigFraction.of(300, 1),
                transaction.getPortionAmountOwedSelf(CARL.getName()));
        assertEquals(BigFraction.ZERO,
                transaction.getPortionAmountOwedSelf(Name.SELF));
    }

    @Test
    public void getAllPortions_singlePortion_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(ALICE_PORTION);
        Transaction transaction = new TransactionBuilder().withAmount("100").withPortions(portions).build();
        Person person = new PersonBuilder().withName(ALICE_PORTION.getPersonName().fullName).build();
        Map<Name, BigFraction> expectedPortions = new HashMap<>();
        expectedPortions.put(person.getName(), BigFraction.of(100, 1));
        assertEquals(expectedPortions, transaction.getAllPortionAmounts());
    }

    @Test
    public void getAllPortions_multiplePortions_returnsCorrectPortion() {
        Set<Portion> portions = Set.of(
            ALICE_PORTION,
            BENSON_PORTION,
            CARL_PORTION
        );
        Transaction transaction = new TransactionBuilder().withAmount("1200").withPortions(portions).build();
        Map<Name, BigFraction> expectedPortions = new HashMap<>();
        expectedPortions.put(new Name(ALICE.getName().toString()), BigFraction.of(200, 1));
        expectedPortions.put(new Name(BENSON.getName().toString()), BigFraction.of(400, 1));
        expectedPortions.put(new Name(CARL.getName().toString()), BigFraction.of(600, 1));
        assertEquals(expectedPortions, transaction.getAllPortionAmounts());
    }

    @Test
    public void isValid() {
        assertFalse(new TransactionBuilder().build().isValid(Set.of()));
        assertFalse(new TransactionBuilder().withPayeeName(Name.SELF.fullName).build().isValid(Set.of()));
        assertFalse(new TransactionBuilder().withPayeeName(Name.SELF.fullName)
                .withAmount("0").build().isValid(Set.of()));
        assertFalse(new TransactionBuilder().withPortions(Set.of(new PortionBuilder()
                .withName(Name.SELF.fullName).build(), ALICE_PORTION)).build().isValid(Set.of()));
        assertFalse(new TransactionBuilder().withPayeeName(Name.SELF.fullName).withPortions(Set.of(new PortionBuilder()
                .withName(Name.SELF.fullName).build(), ALICE_PORTION)).build().isValid(Set.of()));
        assertFalse(new TransactionBuilder().withPayeeName(Name.SELF.fullName).withPortions(Set.of(new PortionBuilder()
                .withName(Name.SELF.fullName).withWeight("0").build(), ALICE_PORTION)).build()
                .isValid(Set.of(ALICE.getName())));
    }
}
