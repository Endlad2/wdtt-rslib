use rand::seq::SliceRandom;
const FIRST: &[&str] = &["Александр", "Максим", "Дмитрий", "Алексей", "Мария", "Анна", "Елена"];
const LAST: &[&str] = &["Иванов", "Петров", "Смирнов", "Кузнецов", "Попов", "Соколова"];
pub fn convertToFemaleSurname(surname: &str) -> String { if surname.ends_with("ов") || surname.ends_with("ев") || surname.ends_with("ин") { format!("{surname}а") } else { surname.into() } }
pub fn generateName() -> String { let mut r=rand::thread_rng(); format!("{} {}", FIRST.choose(&mut r).unwrap(), LAST.choose(&mut r).unwrap()) }
