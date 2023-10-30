package seedu.address.model.transaction;

import static seedu.address.commons.util.CollectionUtil.requireAllNonNull;
import static seedu.address.commons.util.CollectionUtil.requireNonEmptyCollection;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.numbers.fraction.BigFraction;

import seedu.address.commons.util.ToStringBuilder;
import seedu.address.model.person.Name;
import seedu.address.model.transaction.portion.Portion;
import seedu.address.model.transaction.portion.Weight;

/**
 * Represents a Transaction in the address book.
 * Guarantees: details are present and not null, field values are validated, immutable.
 */
public class Transaction implements Comparable<Transaction> {

    // Data fields
    private final Amount amount;
    private final Description description;
    private final Name payeeName;
    private final Set<Portion> portions = new HashSet<>();

    /**
     * Internal timestamp used for uniquely identifying transactions.
     **/
    private final Timestamp timestamp;

    /**
     * Every field must be present and not null.
     */
    public Transaction(Amount amount, Description description, Name payeeName, Set<Portion> portions) {
        this(amount, description, payeeName, portions, Timestamp.now());
    }

    /**
     * Every field must be present and not null.
     */
    public Transaction(Amount amount, Description description, Name payeeName, Set<Portion> portions,
                       Timestamp timestamp) {
        requireAllNonNull(amount, description, payeeName, portions, timestamp);
        requireNonEmptyCollection(portions);
        this.amount = amount;
        this.description = description;
        this.payeeName = payeeName;
        this.portions.addAll(portions);
        this.timestamp = timestamp;
    }

    public Amount getAmount() {
        return amount;
    }

    public Description getDescription() {
        return description;
    }

    public Name getPayeeName() {
        return payeeName;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    /**
     * Returns true if the transaction relates to both the user (`SELF`) and another named person (not `OTHERS`).
     */
    public boolean isRelevant() {
        Set<Name> participants = getAllInvolvedPersonNames();
        if (!participants.contains(Name.SELF)) {
            return false;
        }
        if (Name.RESERVED_NAMES.containsAll(participants)) {
            return false;
        }
        return true;
    }

    /**
     * Returns true if all values (amount and weights)  in the transaction are positive.
     * @return
     */
    public boolean isPositive() {
        if (amount.amount.signum() <= 0) {
            return false;
        }
        for (Portion portion : portions) {
            if (portion.getWeight().value.signum() <= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if we know everyone involved in a transaction.
     */
    public boolean isKnown(Set<Name> validNames) {
        if (!(payeeName.equals(Name.SELF) || validNames.contains(payeeName))) {
            return false;
        }
        for (Portion portion : portions) {
            if (!(validNames.contains(portion.getPersonName())
                    || Name.RESERVED_NAMES.contains(portion.getPersonName()))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if there are no duplicate names in portions.
     */
    public boolean hasNoDuplicates() {
        return portions.stream().map(Portion::getPersonName)
            .collect(Collectors.toSet()).size() == portions.size();
    }

    /**
     * Returns true if a transaction is valid.
     */
    public boolean isValid(Set<Name> validNames) {
        return isRelevant() && isPositive() && isKnown(validNames) && hasNoDuplicates();
    }

    /**
     * Replaces all equal names to names in the set.
     */
    public Transaction syncNames(Set<Name> validNames) {
        Map<Name, Name> nameMap = new HashMap<>();
        for (Name name : validNames) {
            nameMap.put(name, name);
        }
        nameMap.put(Name.SELF, Name.SELF);
        Name newPayee = nameMap.containsKey(payeeName) ? nameMap.get(payeeName) : Name.OTHERS;
        Set<Portion> newPortions = portions.stream().map(x -> new Portion(
                nameMap.containsKey(x.getPersonName()) ? nameMap.get(x.getPersonName()) : Name.OTHERS,
                x.getWeight())).collect(Collectors.toSet());
        return new Transaction(amount, description, newPayee, newPortions, timestamp);
    }

    /**
     * Returns a new {@code Transaction} replacing the person p with others.
     */
    public Transaction removePerson(Name p) {
        Name newPayee = payeeName.equals(p) ? Name.OTHERS : payeeName;
        Set<Portion> newPortions = new HashSet<>();
        BigFraction accumOthers = BigFraction.ZERO;
        for (Portion portion : portions) {
            if (portion.getPersonName().equals(p) || portion.getPersonName().equals(Name.OTHERS)) {
                accumOthers = accumOthers.add(portion.getWeight().value);
            } else {
                newPortions.add(portion);
            }
        }
        if (accumOthers.compareTo(BigFraction.ZERO) > 0) {
            newPortions.add(new Portion(Name.OTHERS, new Weight(accumOthers)));
        }
        return new Transaction(amount, description, newPayee, newPortions, timestamp);
    }

    public Transaction setPerson(Name target, Name editedName) {
        Name newPayee = payeeName.equals(target) ? editedName : payeeName;
        Set<Portion> newPortions = new HashSet<>();
        for (Portion portion : portions) {
            if (portion.getPersonName().equals(target)) {
                newPortions.add(new Portion(editedName, portion.getWeight()));
            } else {
                newPortions.add(portion);
            }
        }
        return new Transaction(amount, description, newPayee, newPortions, timestamp);
    }

    /**
     * Returns an immutable portions set, which throws {@code UnsupportedOperationException}
     * if modification is attempted.
     */
    public Set<Portion> getPortions() {
        return Collections.unmodifiableSet(portions);
    }

    /**
     * Returns a mutable copy of the portions set.
     */
    public Set<Portion> getPortionsCopy() {
        return new HashSet<>(portions);
    }

    /**
     * Returns the portion amount of the transaction that the person has to pay the payee.
     *
     * @param personName the name of the person
     */
    public BigFraction getPortionAmount(Name personName) {
        BigFraction totalWeight = getTotalWeight();
        return portions.stream()
            .filter(portion -> portion.getPersonName().equals(personName))
            .map(portions -> portions.getWeight().value.multiply(this.amount.amount).divide(totalWeight))
            .reduce(BigFraction.ZERO, BigFraction::add);
    }

    /**
     * Returns a map of all the portions with calculated amount each person has to pay the payee for this transaction.
     */
    public Map<Name, BigFraction> getAllPortionAmounts() {
        BigFraction totalWeight = getTotalWeight();
        return portions.stream()
            .collect(
                Collectors.toMap(
                    Portion::getPersonName,
                    portion -> portion.getWeight().value.multiply(this.amount.amount).divide(totalWeight)
                )
            );
    }


    /**
     * Returns the portion amount of the transaction that the person has to pay the user (self).
     * A positive amount indicates the amount the person owes the user.
     * A negative amount indicates the amount the user owes the person.
     * Zero amount indicates that the user has no net balance owed to the user from the transaction.
     *
     * @param personName the name of the person
     */
    public BigFraction getPortionAmountOwedSelf(Name personName) {
        // person is not relevant to user in the transaction
        if (!payeeName.equals(personName) && !payeeName.equals(Name.SELF)) {
            return BigFraction.ZERO;
        }

        // user cannot owe self money
        if (payeeName.equals(Name.SELF) && personName.equals(Name.SELF)) {
            return BigFraction.ZERO;
        }

        // user owes person money from the transaction
        if (payeeName.equals(personName)) {
            return getPortionAmount(Name.SELF).negate();
        }

        // person owes user money from the transaction
        return getPortionAmount(personName);
    }

    /**
     * Returns true if the person with the given name is involved in this transaction, either as a payer or a payee.
     *
     * @param personName the name of the person
     */
    public boolean isPersonInvolved(Name personName) {
        return getAllInvolvedPersonNames().contains(personName);
    }

    /**
     * Returns the names of all the persons involved in this transaction, either as a payer or a payee.
     */
    public Set<Name> getAllInvolvedPersonNames() {
        Set<Name> names = portions.stream()
            .map(Portion::getPersonName)
            .collect(Collectors.toSet());
        names.add(payeeName);
        return names;
    }

    /**
     * Returns true if both transactions have the same amount, description, payeeName, portions and transactions.
     * This defines a weaker notion of equality between two transactions.
     */
    public boolean isSameTransaction(Transaction otherTransaction) {
        if (otherTransaction == this) {
            return true;
        }

        return otherTransaction != null
            && otherTransaction.getAmount().equals(getAmount())
            && otherTransaction.getDescription().equals(getDescription())
            && otherTransaction.getPayeeName().equals(getPayeeName())
            && otherTransaction.getPortions().equals(getPortions())
            && otherTransaction.getTimestamp().equals(getTimestamp());
    }

    /**
     * Returns true if both transactions is the same object.
     */
    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        // instanceof handles nulls
        if (!(other instanceof Transaction)) {
            return false;
        }


        Transaction otherTransaction = (Transaction) other;
        return amount.equals(otherTransaction.amount)
                && payeeName.equals(otherTransaction.payeeName)
                && description.equals(otherTransaction.description)
                && portions.equals(otherTransaction.portions)
                && timestamp.equals(otherTransaction.timestamp);

    }

    @Override
    public int compareTo(Transaction other) {
        return other.timestamp.compareTo(this.timestamp);
    }

    @Override
    public int hashCode() {
        // use this method for custom fields hashing instead of implementing your own
        return Objects.hash(amount, description, payeeName, portions);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
            .add("amount", amount)
            .add("description", description)
            .add("payeeName", payeeName)
            .add("portions", portions)
            .toString();
    }

    private BigFraction getTotalWeight() {
        return portions.stream()
            .map(portion -> portion.getWeight().value)
            .reduce(BigFraction.ZERO, BigFraction::add);
    }
}
