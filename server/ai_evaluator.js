'use strict';

/**
 * Admission — DB-backed challenge evaluator
 *
 * Selects 2 random questions from the `admission_questions` table.
 * The correct answers are never sent to the client.
 */

function generateChallenge(db) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT id, question, options FROM admission_questions ORDER BY RANDOM() LIMIT 2',
      [],
      (err, rows) => {
        if (err || !rows || rows.length < 2) {
          return reject(err || new Error('Not enough questions available.'));
        }
        resolve({
          type: 'multiple_choice',
          questions: rows.map(r => ({
            id: r.id,
            question: r.question,
            options: JSON.parse(r.options),
          })),
        });
      }
    );
  });
}

function evaluateResponse(db, questions, answers) {
  return new Promise((resolve) => {
    if (!questions || questions.length !== 2 || !answers) {
      return resolve({ qualified: false, reason: 'Invalid request.' });
    }

    const ids = questions.map(q => q.id);
    db.all(
      `SELECT id, correct_answer FROM admission_questions WHERE id IN (${ids.map(() => '?').join(',')})`,
      ids,
      (err, rows) => {
        if (err || !rows || rows.length !== 2) {
          return resolve({ qualified: false, reason: 'Internal error.' });
        }

        const correctMap = {};
        for (const row of rows) correctMap[row.id] = row.correct_answer;

        for (const q of questions) {
          const userAnswer = ((answers[q.id] || '')).trim().toUpperCase();
          if (userAnswer !== correctMap[q.id]) {
            return resolve({
              qualified: false,
              reason: 'One or more answers are incorrect.',
            });
          }
        }

        resolve({ qualified: true, reason: 'Admission approved.' });
      }
    );
  });
}

module.exports = {
  generateChallenge,
  evaluateResponse,
};
