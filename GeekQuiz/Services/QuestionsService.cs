// ----------------------------------------------------------------------------------
// Microsoft Developer & Platform Evangelism
// 
// Copyright (c) Microsoft Corporation. All rights reserved.
// 
// THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
// EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES 
// OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
// ----------------------------------------------------------------------------------
// The example companies, organizations, products, domain names,
// e-mail addresses, logos, people, places, and events depicted
// herein are fictitious.  No association with any real company,
// organization, product, domain name, email address, logo, person,
// places, or events is intended or should be inferred.
// ----------------------------------------------------------------------------------

using GeekQuiz.Models;
using System.Linq;
using System.Threading.Tasks;
using System.Data.Entity;
using System.Threading;

namespace GeekQuiz.Services
{
    public class QuestionsService
    {
        private TriviaContext db;

        public QuestionsService(TriviaContext db)
        {
            this.db = db;
        }

        public async Task<TriviaQuestion> NextQuestionAsync(string userId)
        {
            var lastQuestionId = await db.TriviaAnswers
                .Where(a => a.UserId == userId)
                .GroupBy(a => a.QuestionId)
                .Select(g => new { QuestionId = g.Key, Count = g.Count() })
                .OrderByDescending(q => new { q.Count, QuestionId = q.QuestionId })
                .Select(q => q.QuestionId)
                .FirstOrDefaultAsync();

            var questionsCount = await db.TriviaQuestions.CountAsync();

            var nextQuestionId = (lastQuestionId % questionsCount) + 1;
            return await db.TriviaQuestions.FindAsync(CancellationToken.None, nextQuestionId);
        }
    }
}