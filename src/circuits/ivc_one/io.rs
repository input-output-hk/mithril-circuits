use crate::{
    Accumulator, Msm, Point, PolynomialLabel,
    ivc_one::{C, F, S},
};
use midnight_curves::serde::SerdeObject;
use midnight_proofs::utils::{SerdeFormat, helpers::ProcessedSerdeObject};
use std::io;

pub trait Write {
    fn write<W: io::Write>(&self, w: &mut W, format: SerdeFormat) -> io::Result<()>;
}
pub trait Read: Sized {
    fn read<R: io::Read>(r: &mut R, format: SerdeFormat) -> io::Result<Self>;
}

// Tags of the `PolynomialLabel` variants in the serialised form.
const LABEL_FIXED: u8 = 0;
const LABEL_ADVICE: u8 = 1;
const LABEL_COMMITTED_INSTANCE: u8 = 2;
const LABEL_PERMUTATION_FIXED: u8 = 3;
const LABEL_PERMUTATION_ACCUMULATOR: u8 = 4;
const LABEL_LOGUP_HELPER: u8 = 5;
const LABEL_LOGUP_MULTIPLICITIES: u8 = 6;
const LABEL_LOGUP_AGGREGATOR: u8 = 7;
// Tag 8 is reserved for the removed Linearization variant.
const LABEL_QUOTIENT: u8 = 9;
const LABEL_QUOTIENT_PIECE: u8 = 10;
const LABEL_TRASH: u8 = 11;
const LABEL_CUSTOM: u8 = 12;
const LABEL_NO_LABEL: u8 = 13;
const LABEL_COLLECTION: u8 = 14;

// Tags of the `Point` variants in the serialised form.
const POINT_VARIABLE: u8 = 0;
const POINT_FIXED: u8 = 1;

fn write_u32<W: io::Write>(writer: &mut W, n: usize) -> io::Result<()> {
    let n = u32::try_from(n)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length exceeds u32"))?;
    writer.write_all(&n.to_le_bytes())
}

fn read_u32<R: io::Read>(reader: &mut R) -> io::Result<usize> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn read_u8<R: io::Read>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn write_label<W: io::Write>(writer: &mut W, label: &PolynomialLabel) -> io::Result<()> {
    let mut tagged = |tag: u8, indices: &[usize]| -> io::Result<()> {
        writer.write_all(&[tag])?;
        indices.iter().try_for_each(|i| write_u32(writer, *i))
    };
    match label {
        PolynomialLabel::Fixed(i) => tagged(LABEL_FIXED, &[*i]),
        PolynomialLabel::Advice(i) => tagged(LABEL_ADVICE, &[*i]),
        PolynomialLabel::CommittedInstance(i) => tagged(LABEL_COMMITTED_INSTANCE, &[*i]),
        PolynomialLabel::PermutationFixed(i) => tagged(LABEL_PERMUTATION_FIXED, &[*i]),
        PolynomialLabel::PermutationAccumulator(i) => {
            tagged(LABEL_PERMUTATION_ACCUMULATOR, &[*i])
        }
        PolynomialLabel::LogupHelper(i, j) => tagged(LABEL_LOGUP_HELPER, &[*i, *j]),
        PolynomialLabel::LogupMultiplicities(i) => tagged(LABEL_LOGUP_MULTIPLICITIES, &[*i]),
        PolynomialLabel::LogupAggregator(i) => tagged(LABEL_LOGUP_AGGREGATOR, &[*i]),
        PolynomialLabel::Quotient => tagged(LABEL_QUOTIENT, &[]),
        PolynomialLabel::QuotientPiece(i) => tagged(LABEL_QUOTIENT_PIECE, &[*i]),
        PolynomialLabel::Trash(i) => tagged(LABEL_TRASH, &[*i]),
        PolynomialLabel::NoLabel => tagged(LABEL_NO_LABEL, &[]),
        PolynomialLabel::Collection(labels) => {
            writer.write_all(&[LABEL_COLLECTION])?;
            write_u32(writer, labels.len())?;
            labels
                .iter()
                .try_for_each(|label| write_label(writer, label))
        }
        PolynomialLabel::Custom(name) => {
            writer.write_all(&[LABEL_CUSTOM])?;
            write_u32(writer, name.len())?;
            writer.write_all(name.as_bytes())
        }
    }
}

fn read_label<R: io::Read>(reader: &mut R) -> io::Result<PolynomialLabel> {
    let tag = read_u8(reader)?;
    Ok(match tag {
        LABEL_FIXED => PolynomialLabel::Fixed(read_u32(reader)?),
        LABEL_ADVICE => PolynomialLabel::Advice(read_u32(reader)?),
        LABEL_COMMITTED_INSTANCE => PolynomialLabel::CommittedInstance(read_u32(reader)?),
        LABEL_PERMUTATION_FIXED => PolynomialLabel::PermutationFixed(read_u32(reader)?),
        LABEL_PERMUTATION_ACCUMULATOR => {
            PolynomialLabel::PermutationAccumulator(read_u32(reader)?)
        }
        LABEL_LOGUP_HELPER => {
            let i = read_u32(reader)?;
            let j = read_u32(reader)?;
            PolynomialLabel::LogupHelper(i, j)
        }
        LABEL_LOGUP_MULTIPLICITIES => PolynomialLabel::LogupMultiplicities(read_u32(reader)?),
        LABEL_LOGUP_AGGREGATOR => PolynomialLabel::LogupAggregator(read_u32(reader)?),
        LABEL_QUOTIENT => PolynomialLabel::Quotient,
        LABEL_QUOTIENT_PIECE => PolynomialLabel::QuotientPiece(read_u32(reader)?),
        LABEL_TRASH => PolynomialLabel::Trash(read_u32(reader)?),
        LABEL_NO_LABEL => PolynomialLabel::NoLabel,
        LABEL_COLLECTION => {
            let len = read_u32(reader)?;
            PolynomialLabel::Collection(
                (0..len)
                    .map(|_| read_label(reader))
                    .collect::<io::Result<_>>()?,
            )
        }
        LABEL_CUSTOM => {
            let len = read_u32(reader)?;
            let mut bytes = vec![0u8; len];
            reader.read_exact(&mut bytes)?;
            let name = String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 label")
            })?;
            PolynomialLabel::Custom(name)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown polynomial label tag {tag}"),
            ));
        }
    })
}

/// An MSM is serialised as its number of terms followed by, for each term, the
/// base (a tag and, for variable bases, the point), the scalar and the label.
impl Write for Msm<S> {
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        let bases = self.bases();
        let scalars = self.scalars();
        let labels = self.labels();

        write_u32(writer, bases.len())?;
        for ((base, scalar), label) in bases.iter().zip(scalars.iter()).zip(labels.iter()) {
            match base {
                Point::Variable(point) => {
                    writer.write_all(&[POINT_VARIABLE])?;
                    point.write(writer, format)?;
                }
                Point::Fixed => writer.write_all(&[POINT_FIXED])?,
            }
            scalar.write_raw(writer)?;
            write_label(writer, label)?;
        }

        Ok(())
    }
}

impl Read for Msm<S> {
    fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Msm<S>> {
        let len = read_u32(reader)?;

        let mut bases = Vec::with_capacity(len);
        let mut scalars = Vec::with_capacity(len);
        let mut labels = Vec::with_capacity(len);
        for _ in 0..len {
            let base = match read_u8(reader)? {
                POINT_VARIABLE => Point::Variable(C::read(reader, format)?),
                POINT_FIXED => Point::Fixed,
                tag => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown point tag {tag}"),
                    ));
                }
            };
            bases.push(base);
            scalars.push(F::read_raw(reader)?);
            labels.push(read_label(reader)?);
        }

        Ok(Msm::new(&bases, &scalars, &labels))
    }
}

impl Write for Accumulator<S> {
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        self.lhs().write(writer, format)?;
        self.rhs().write(writer, format)
    }
}

impl Read for Accumulator<S> {
    fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self> {
        let lhs = Msm::read(reader, format)?;
        let rhs = Msm::read(reader, format)?;
        Ok(Accumulator::<S>::new(lhs, rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_labels_round_trip() {
        let labels = vec![
            PolynomialLabel::Fixed(1),
            PolynomialLabel::Advice(2),
            PolynomialLabel::CommittedInstance(3),
            PolynomialLabel::PermutationFixed(4),
            PolynomialLabel::PermutationAccumulator(5),
            PolynomialLabel::LogupHelper(6, 7),
            PolynomialLabel::LogupMultiplicities(8),
            PolynomialLabel::LogupAggregator(9),
            PolynomialLabel::Quotient,
            PolynomialLabel::QuotientPiece(10),
            PolynomialLabel::Trash(11),
            PolynomialLabel::Custom("cert_vk/Fixed(0)".into()),
            PolynomialLabel::NoLabel,
            PolynomialLabel::Collection(vec![
                PolynomialLabel::Fixed(0),
                PolynomialLabel::Collection(vec![PolynomialLabel::PermutationFixed(1)]),
            ]),
        ];
        let mut bytes = Vec::new();
        for label in &labels {
            write_label(&mut bytes, label).unwrap();
        }
        let mut reader = bytes.as_slice();
        for label in labels {
            assert_eq!(read_label(&mut reader).unwrap(), label);
        }
        assert!(reader.is_empty());
    }

    #[test]
    fn removed_linearization_tag_is_rejected() {
        let error = read_label(&mut &[8u8][..]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
