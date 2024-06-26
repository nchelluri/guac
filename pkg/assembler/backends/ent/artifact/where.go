// Code generated by ent, DO NOT EDIT.

package artifact

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uuid.UUID) predicate.Artifact {
	return predicate.Artifact(sql.FieldLTE(FieldID, id))
}

// Algorithm applies equality check predicate on the "algorithm" field. It's identical to AlgorithmEQ.
func Algorithm(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldAlgorithm, v))
}

// Digest applies equality check predicate on the "digest" field. It's identical to DigestEQ.
func Digest(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldDigest, v))
}

// AlgorithmEQ applies the EQ predicate on the "algorithm" field.
func AlgorithmEQ(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldAlgorithm, v))
}

// AlgorithmNEQ applies the NEQ predicate on the "algorithm" field.
func AlgorithmNEQ(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldNEQ(FieldAlgorithm, v))
}

// AlgorithmIn applies the In predicate on the "algorithm" field.
func AlgorithmIn(vs ...string) predicate.Artifact {
	return predicate.Artifact(sql.FieldIn(FieldAlgorithm, vs...))
}

// AlgorithmNotIn applies the NotIn predicate on the "algorithm" field.
func AlgorithmNotIn(vs ...string) predicate.Artifact {
	return predicate.Artifact(sql.FieldNotIn(FieldAlgorithm, vs...))
}

// AlgorithmGT applies the GT predicate on the "algorithm" field.
func AlgorithmGT(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldGT(FieldAlgorithm, v))
}

// AlgorithmGTE applies the GTE predicate on the "algorithm" field.
func AlgorithmGTE(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldGTE(FieldAlgorithm, v))
}

// AlgorithmLT applies the LT predicate on the "algorithm" field.
func AlgorithmLT(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldLT(FieldAlgorithm, v))
}

// AlgorithmLTE applies the LTE predicate on the "algorithm" field.
func AlgorithmLTE(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldLTE(FieldAlgorithm, v))
}

// AlgorithmContains applies the Contains predicate on the "algorithm" field.
func AlgorithmContains(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldContains(FieldAlgorithm, v))
}

// AlgorithmHasPrefix applies the HasPrefix predicate on the "algorithm" field.
func AlgorithmHasPrefix(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldHasPrefix(FieldAlgorithm, v))
}

// AlgorithmHasSuffix applies the HasSuffix predicate on the "algorithm" field.
func AlgorithmHasSuffix(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldHasSuffix(FieldAlgorithm, v))
}

// AlgorithmEqualFold applies the EqualFold predicate on the "algorithm" field.
func AlgorithmEqualFold(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEqualFold(FieldAlgorithm, v))
}

// AlgorithmContainsFold applies the ContainsFold predicate on the "algorithm" field.
func AlgorithmContainsFold(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldContainsFold(FieldAlgorithm, v))
}

// DigestEQ applies the EQ predicate on the "digest" field.
func DigestEQ(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEQ(FieldDigest, v))
}

// DigestNEQ applies the NEQ predicate on the "digest" field.
func DigestNEQ(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldNEQ(FieldDigest, v))
}

// DigestIn applies the In predicate on the "digest" field.
func DigestIn(vs ...string) predicate.Artifact {
	return predicate.Artifact(sql.FieldIn(FieldDigest, vs...))
}

// DigestNotIn applies the NotIn predicate on the "digest" field.
func DigestNotIn(vs ...string) predicate.Artifact {
	return predicate.Artifact(sql.FieldNotIn(FieldDigest, vs...))
}

// DigestGT applies the GT predicate on the "digest" field.
func DigestGT(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldGT(FieldDigest, v))
}

// DigestGTE applies the GTE predicate on the "digest" field.
func DigestGTE(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldGTE(FieldDigest, v))
}

// DigestLT applies the LT predicate on the "digest" field.
func DigestLT(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldLT(FieldDigest, v))
}

// DigestLTE applies the LTE predicate on the "digest" field.
func DigestLTE(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldLTE(FieldDigest, v))
}

// DigestContains applies the Contains predicate on the "digest" field.
func DigestContains(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldContains(FieldDigest, v))
}

// DigestHasPrefix applies the HasPrefix predicate on the "digest" field.
func DigestHasPrefix(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldHasPrefix(FieldDigest, v))
}

// DigestHasSuffix applies the HasSuffix predicate on the "digest" field.
func DigestHasSuffix(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldHasSuffix(FieldDigest, v))
}

// DigestEqualFold applies the EqualFold predicate on the "digest" field.
func DigestEqualFold(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldEqualFold(FieldDigest, v))
}

// DigestContainsFold applies the ContainsFold predicate on the "digest" field.
func DigestContainsFold(v string) predicate.Artifact {
	return predicate.Artifact(sql.FieldContainsFold(FieldDigest, v))
}

// HasOccurrences applies the HasEdge predicate on the "occurrences" edge.
func HasOccurrences() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, OccurrencesTable, OccurrencesColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasOccurrencesWith applies the HasEdge predicate on the "occurrences" edge with a given conditions (other predicates).
func HasOccurrencesWith(preds ...predicate.Occurrence) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newOccurrencesStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasSbom applies the HasEdge predicate on the "sbom" edge.
func HasSbom() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, SbomTable, SbomColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasSbomWith applies the HasEdge predicate on the "sbom" edge with a given conditions (other predicates).
func HasSbomWith(preds ...predicate.BillOfMaterials) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newSbomStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasAttestations applies the HasEdge predicate on the "attestations" edge.
func HasAttestations() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, AttestationsTable, AttestationsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasAttestationsWith applies the HasEdge predicate on the "attestations" edge with a given conditions (other predicates).
func HasAttestationsWith(preds ...predicate.SLSAAttestation) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newAttestationsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasAttestationsSubject applies the HasEdge predicate on the "attestations_subject" edge.
func HasAttestationsSubject() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, AttestationsSubjectTable, AttestationsSubjectColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasAttestationsSubjectWith applies the HasEdge predicate on the "attestations_subject" edge with a given conditions (other predicates).
func HasAttestationsSubjectWith(preds ...predicate.SLSAAttestation) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newAttestationsSubjectStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasHashEqualArtA applies the HasEdge predicate on the "hash_equal_art_a" edge.
func HasHashEqualArtA() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, HashEqualArtATable, HashEqualArtAColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHashEqualArtAWith applies the HasEdge predicate on the "hash_equal_art_a" edge with a given conditions (other predicates).
func HasHashEqualArtAWith(preds ...predicate.HashEqual) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newHashEqualArtAStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasHashEqualArtB applies the HasEdge predicate on the "hash_equal_art_b" edge.
func HasHashEqualArtB() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, HashEqualArtBTable, HashEqualArtBColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHashEqualArtBWith applies the HasEdge predicate on the "hash_equal_art_b" edge with a given conditions (other predicates).
func HasHashEqualArtBWith(preds ...predicate.HashEqual) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newHashEqualArtBStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasVex applies the HasEdge predicate on the "vex" edge.
func HasVex() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, VexTable, VexColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasVexWith applies the HasEdge predicate on the "vex" edge with a given conditions (other predicates).
func HasVexWith(preds ...predicate.CertifyVex) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newVexStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasCertification applies the HasEdge predicate on the "certification" edge.
func HasCertification() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, CertificationTable, CertificationColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCertificationWith applies the HasEdge predicate on the "certification" edge with a given conditions (other predicates).
func HasCertificationWith(preds ...predicate.Certification) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newCertificationStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasMetadata applies the HasEdge predicate on the "metadata" edge.
func HasMetadata() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, MetadataTable, MetadataColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasMetadataWith applies the HasEdge predicate on the "metadata" edge with a given conditions (other predicates).
func HasMetadataWith(preds ...predicate.HasMetadata) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newMetadataStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasPoc applies the HasEdge predicate on the "poc" edge.
func HasPoc() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, PocTable, PocColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasPocWith applies the HasEdge predicate on the "poc" edge with a given conditions (other predicates).
func HasPocWith(preds ...predicate.PointOfContact) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newPocStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasIncludedInSboms applies the HasEdge predicate on the "included_in_sboms" edge.
func HasIncludedInSboms() predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, IncludedInSbomsTable, IncludedInSbomsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasIncludedInSbomsWith applies the HasEdge predicate on the "included_in_sboms" edge with a given conditions (other predicates).
func HasIncludedInSbomsWith(preds ...predicate.BillOfMaterials) predicate.Artifact {
	return predicate.Artifact(func(s *sql.Selector) {
		step := newIncludedInSbomsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Artifact) predicate.Artifact {
	return predicate.Artifact(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Artifact) predicate.Artifact {
	return predicate.Artifact(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Artifact) predicate.Artifact {
	return predicate.Artifact(sql.NotPredicates(p))
}
